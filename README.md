# Detección de Amenazas en Windows 3: Cyber Kill Chain
**Análisis forense basado en el ciclo de vida del adversario.** Investigación respaldada en los laboratorios prácticos del módulo **Windows Threat Detection 3** de **TryHackMe**, evaluando la telemetría de `Sysmon.evtx` y `Security.evtx` para reconstruir la línea de tiempo de un ataque real.

## 🟢 INFORME SOC: DETECCIÓN DE AMENAZAS EN WINDOWS
### 🔵 Análisis Forense basado en el Ciclo de Vida del Adversario (Cyber Kill Chain)

* **ANALISTA RESPONSABLE:** Sebastián Navarro M.
* **ENTORNO EVALUADO:** TryHackMe - Windows Threat Detection 3
* **REGISTROS ANALIZADOS:** `Sysmon.evtx` & `Security.evtx`

---
> 🎥 **DEMOSTRACIÓN TÉCNICA EN VIDEO (WALKTHROUGH)**
> 
> Para una revisión rápida del caso de estudio, puedes acceder directamente a las investigaciones guiadas en video divididas por fases operacionales:
> 
> * 🎬 **Parte 1 — Acceso Inicial y Delivery:** [Ver demostración en video](PEGA_AQUI_LINK_VIDEO_1) *(Análisis de Fuerza Bruta RDP y Carga de Payload)*
> * 🎬 **Parte 2 — Persistencia y Escalada:** [Ver demostración en video](PEGA_AQUI_LINK_VIDEO_2) *(Detección de Cuenta Trampa, Servicios y Tareas Programadas)*
> * 🎬 **Parte 3 — Comando, Control (C2) y Triaje:** [Ver demostración en video](PEGA_AQUI_LINK_VIDEO_3) *(Telemetría Sysmon ID 1 / ID 22 y Diagnóstico Forense)*

---

## 🟢 Introducción y Contexto del Laboratorio

Como analista SOC, desarrollé este informe basándome en el entorno práctico del módulo *Windows Threat Detection 3* de TryHackMe. El objetivo de este caso de estudio es demostrar la capacidad de analizar un incidente cibernético completo. En lugar de reportar eventos aislados, correlacioné cada hallazgo técnico con las fases de la Cyber Kill Chain, documentando paso a paso cómo el atacante logró entrar, qué herramientas ejecutó y cómo aseguró su control sobre la máquina.

---
## Fase 1: Acceso Inicial (Initial Access)

### Análisis Narrativo y Razonamiento
En esta primera fase investigué cómo el atacante logró romper el perímetro de autenticación del servidor. Al revisar los registros de auditoría en `Security.evtx` (telemetría de Windows Threat Detection 1), mi primer razonamiento fue buscar signos de un intento de intrusión por la fuerza. Para corroborar esta hipótesis, filtré por el **Event ID 4625** (inicio de sesión fallido).

El resultado reveló una ráfaga masiva y constante de autenticaciones fallidas dirigidas contra la cuenta `Administrator`. La frecuencia de estos eventos (registrados segundo a segundo) confirmó de inmediato el uso de una herramienta automatizada ejecutando un ataque de diccionario.

Sabiendo que un atacante no se detiene en los intentos fallidos, la duda lógica que surgió fue: *¿logró adivinar la credencial?* Para responder a esto, cambié el filtro al **Event ID 4624** (inicio de sesión exitoso). Al analizar los eventos posteriores a la ráfaga, confirmé que el 20 de mayo de 2025 a las 09:51:48 se consolidó la intrusión con un acceso exitoso a la cuenta `Administrator`. Al inspeccionar el detalle técnico, identifiqué un **Logon Type 10**, lo que demostró que el acceso se realizó de forma interactiva y remota a través de RDP. En la sección *Network Information* (campos *Source Network Address* y *Workstation Name*), registré la dirección IP y el nombre del equipo utilizado por el atacante para penetrar el sistema.

### Ficha Técnica de Hallazgos
* **Objetivo:** Identificar el vector de entrada y confirmar el compromiso del servidor.
* **Fuente de datos:** `Security.evtx` (Windows Threat Detection 1).
* **Análisis de Fuerza Bruta:**
  * **Event ID:** `4625` (An Account Failed to Log On).
  * **Comportamiento:** Ráfaga masiva y automatizada contra la cuenta `Administrator`.
  * **Frecuencia:** Intentos fallidos segundo a segundo (ataque de diccionario).
* **Consolidación de Acceso:**
  * **Event ID:** `4624` (An Account Was Successfully Logged On).
  * **Fecha y Hora:** 20/05/2025 a las 09:51:48.
  * **Tipo de Inicio de Sesión:** `Logon Type 10` (Remote Interactive / RDP).
  * **Cuenta Compromedida:** `Administrator`.
  * **Evidencia Técnica:** Dirección IP de origen y nombre del equipo atacante registrados en el apartado *Network Information* (*Source Network Address* y *Workstation Name*).

---

## Fase 2: Persistencia Inicial y Elevación de Privilegios

### Análisis Narrativo y Razonamiento
Una vez que el atacante estuvo dentro del sistema mediante RDP con la cuenta `Administrator`, su siguiente movimiento lógico era asegurar una vía de acceso secundaria. Como analista, sé que los atacantes prevén que la contraseña del administrador principal pueda ser cambiada o su sesión revocada. Por lo tanto, mi hipótesis fue que el atacante crearía una cuenta local de respaldo durante esa misma sesión interactiva.

Para verificar esta sospecha, filtré en `Security.evtx` por el **Event ID 4720** (creación de cuenta de usuario). La búsqueda confirmó la hipótesis: desde la sesión RDP activa de `Administrator` se creó la cuenta de usuario local `support`. 

Sin embargo, una cuenta estándar no le serviría de mucho para controlar el servidor. El siguiente paso del atacante tenía que ser otorgarle privilegios totales. Para auditar este movimiento, filtré por el **Event ID 4732** (incorporación de un miembro a un grupo local de seguridad). Ahí descubrí que la cuenta `support` fue agregada inmediatamente al grupo `Administrators`. Con esto, el atacante dejó configurada una puerta trasera interactiva legítima en apariencia para reconectarse cuando lo deseara.

### Ficha Técnica de Hallazgos
* **Objetivo:** Rastrear la creación de cuentas locales de respaldo para mantener acceso secundario.
* **Fuente de datos:** `Security.evtx` (Windows Threat Detection 1).
* **Creación de Cuenta Local:**
  * **Event ID:** `4720` (A user account was created).
  * **Cuenta Creada:** `support`.
  * **Origen:** Sesión activa de RDP bajo la cuenta `Administrator`.
* **Elevación de Privilegios:**
  * **Event ID:** `4732` (A member was added to a security-enabled local group).
  * **Grupo Destino:** `Administrators`.
  * **Impacto:** Otorgamiento de privilegios administrativos completos a la nueva cuenta `support`.

---

## Fase 3: Entrega de Carga Útil (Payload Delivery)

### Análisis Narrativo y Razonamiento
Con la persistencia de usuario garantizada, la investigación debía determinar qué herramientas o malware ingresó el atacante al servidor para comenzar a operar. Para este análisis de comportamiento en la máquina, correlacioné la línea de tiempo cambiando a la telemetría de `Sysmon` en el laboratorio Windows Threat Detection 3.

Mi razonamiento analítico consistió en buscar la creación de archivos sospechosos en el sistema generados durante la ventana temporal de la sesión activa del atacante. Al filtrar por el **Event ID 11** de Sysmon (File Creation), identifiqué la descarga y creación del archivo `Urgent.inc.doc.Zone.Identifier`. 

La estructura del nombre presentó de inmediato una anomalía: el uso de una doble extensión (`.inc.doc`), una técnica clásica de evasión para engañar al usuario o a los controles básicos del sistema. Esto confirmó que el atacante utilizó la sesión de administrador para descargar directamente su carga útil desde un servidor externo.

### Ficha Técnica de Hallazgos
* **Objetivo:** Identificar la descarga e inoculación de ejecutable malicioso dentro del sistema.
* **Fuente de datos:** Registros de `Sysmon` (Windows Threat Detection 3).
* **Detección de Archivo Malicioso:**
  * **Event ID (Sysmon):** `11` (FileCreate / File Creation).
  * **Nombre de Archivo:** `Urgent.inc.doc.Zone.Identifier`.
  * **Indicador de Compromiso (IOC):** Estructura de nombre con doble extensión (`.inc.doc`).
  * **Mecanismo:** Descarga directa desde servidor externo durante la sesión activa de administrador.

---

## Fase 4: Persistencia Avanzada (Advanced Persistence)

### Análisis Narrativo y Razonamiento
Entendiendo la psicología del atacante, una cuenta de usuario alternativa no es suficiente garantía: si el servidor se reinicia o el equipo de SOC detecta al usuario `support`, el atacante pierde el acceso. Por lo tanto, el atacante necesita mecanismos que ejecuten su malware de forma automática sin depender de que un usuario inicie sesión. Para rastrear estos mecanismos invisibles, volví a auditar los registros del sistema en `Security.evtx`.

En primer lugar, busqué la creación de servicios maliciosos filtrando por el **Event ID 4697** (instalación de un servicio en el sistema). Detecté la instalación de un servicio configurado con un nombre engañoso: `Data Protection Service`. Al examinar el campo *Service File Name*, descubrí que en realidad apuntaba a la ejecución del binario `nessus.exe`.

En segundo lugar, asumiendo que un atacante precavido establece capas de redundancia por si el servicio es descubierto y eliminado, investigué la creación de tareas programadas filtrando por el **Event ID 4698**. El hallazgo confirmó la redundancia: se creó la tarea programada `Amazon Sync`, cuya ruta de ejecución apuntaba al binario `troy.exe` alojado en `C:\Program Files\Common Files\troy.exe`. Ambas configuraciones le garantizaban al atacante la reconexión automática tras cualquier reinicio del sistema.

### Ficha Técnica de Hallazgos
* **Objetivo:** Documentar mecanismos de ejecución automática del malware resistentes a reinicios.
* **Fuente de datos:** `Security.evtx` (Windows Threat Detection 3).
* **Mecanismo Primario (Servicio Malicioso):**
  * **Event ID:** `4697` (A service was installed in the system).
  * **Nombre del Servicio:** `Data Protection Service`.
  * **Ruta del Ejecutable (*Service File Name*):** `nessus.exe`.
* **Mecanismo Redundante (Tarea Programada):**
  * **Event ID:** `4698` (A scheduled task was created).
  * **Nombre de la Tarea:** `Amazon Sync`.
  * **Ruta del Ejecutable:** `C:\Program Files\Common Files\troy.exe`.

---

## Fase 5: Comando y Control (C2 - Command & Control)

### Análisis Narrativo y Razonamiento
En la fase final del análisis, mi objetivo fue verificar si los mecanismos de persistencia creados funcionaron tras un reinicio del sistema y cómo el malware establecía comunicación con el exterior. Para evaluar la actividad a nivel de procesos y red, volví a consultar los registros de `Sysmon`.

Para rastrear la ejecución del proceso, filtré por el **Event ID 1** de Sysmon (Process Creation) enfocado en el proceso padre `services.exe`. Verifiqué que, al arrancar el sistema operativo, `services.exe` levantó automáticamente el servicio falso `Data Protection Service`, iniciando el binario malicioso en segundo plano sin intervención humana.

Finalmente, para comprobar la salida hacia internet y la infraestructura del atacante, filtré por el **Event ID 22** de Sysmon (DNS Query). En el campo *QueryName*, identifiqué las peticiones de resolución de nombres DNS realizadas por el ejecutable malicioso buscando la IP de su servidor C2. Con este hallazgo se confirmó la apertura de un canal de comunicación bidireccional saliente, completando la investigación del ciclo de vida del ataque.

### Ficha Técnica de Hallazgos
* **Objetivo:** Confirmar la activación automática del malware post-reinicio y la generación de tráfico C2.
* **Fuente de datos:** Registros de `Sysmon` (Windows Threat Detection 3).
* **Ejecución de Proceso:**
  * **Event ID (Sysmon):** `1` (Process Creation).
  * **Proceso Padre (*ParentImage*):** `services.exe`.
  * **Comportamiento:** Activación automática del binario malicioso por parte de `services.exe` mediante el servicio `Data Protection Service`.
* **Canal de Comunicación C2:**
  * **Event ID (Sysmon):** `22` (DNSEvent - DNS query).
  * **Campo Clave (*QueryName*):** Petición de resolución DNS generada por el proceso persistente hacia la infraestructura externa del atacante.

INFORME OPCION 2 CUENTA UNA HISTORIA ORDEN CORRECTO
## Fase 1: Acceso Inicial (Initial Access)

En esta primera fase investigué cómo el atacante logró romper el perímetro de autenticación del servidor. Al revisar los registros de auditoría en `Security.evtx` (correspondientes a la telemetría de Windows Threat Detection 1), mi primer razonamiento fue buscar signos de un intento de intrusión por la fuerza. Para comprobar esta hipótesis, filtré por el **Event ID 4625** (inicio de sesión fallido).

El resultado reveló una ráfaga masiva y constante de autenticaciones fallidas dirigidas contra la cuenta `Administrator`. La frecuencia de estos eventos (registrados segundo a segundo) confirmó de inmediato el uso de una herramienta automatizada ejecutando un ataque de diccionario.

Sabiendo que un atacante no se detiene en los intentos fallidos, la duda lógica que surgió fue: *¿logró adivinar la credencial?* Para responder a esto, cambié el filtro al **Event ID 4624** (inicio de sesión exitoso). Al analizar los eventos posteriores a la ráfaga, confirmé que el 20 de mayo de 2025 a las 09:51:48 se consolidó la intrusión con un acceso exitoso a la cuenta `Administrator`. Al inspeccionar el detalle técnico, identifiqué un **Logon Type 10**, lo que demostró que el acceso se realizó de forma interactiva y remota a través de RDP. En la sección *Network Information* (campos *Source Network Address* y *Workstation Name*), registré la dirección IP y el nombre del equipo utilizado por el atacante para penetrar el sistema.

---

## Fase 2: Persistencia Inicial y Elevación de Privilegios

Una vez que el atacante estuvo dentro del sistema mediante RDP con la cuenta `Administrator`, su siguiente movimiento lógico era asegurar una vía de acceso secundaria. Como analista, sé que los atacantes prevén que la contraseña del administrador principal pueda ser cambiada o su sesión revocada. Por lo tanto, mi hipótesis fue que el atacante crearía una cuenta local de respaldo durante esa misma sesión interactiva.

Para verificar esta sospecha, filtré en `Security.evtx` por el **Event ID 4720** (creación de un cuenta de usuario). La búsqueda confirmó la hipótesis: desde la sesión RDP activa de `Administrator` se creó la cuenta de usuario local `support`. 

Sin embargo, una cuenta estándar no le serviría de mucho para controlar el servidor. El siguiente paso del atacante tenía que ser otorgarle privilegios totales. Para auditar este movimiento, filtré por el **Event ID 4732** (incorporación de un miembro a un grupo local de seguridad). Ahí descubrí que la cuenta `support` fue agregada inmediatamente al grupo `Administrators`. Con esto, el atacante dejó configurada una puerta trasera interactiva legítima en apariencia para reconectarse cuando lo deseara.

---

## Fase 3: Entrega de Carga Útil (Payload Delivery)

Con la persistencia de usuario garantizada, la investigación debía determinar qué herramientas o malware ingresó el atacante al servidor para comenzar a operar. Para este análisis de comportamiento en la máquina, correlacioné la línea de tiempo cambiando a la telemetría de `Sysmon` en el laboratorio Windows Threat Detection 3.

Mi razonamiento analítico consistió en buscar la creación de archivos sospechosos en el sistema generados durante la ventana temporal de la sesión activa del atacante. Al filtrar por el **Event ID 11** de Sysmon (File Creation), identifiqué la descarga y creación del archivo `Urgent.inc.doc.Zone.Identifier`. 

La estructura del nombre presentó de inmediato una anomalía: el uso de una doble extensión (`.inc.doc`), una técnica clásica de evasión para engañar al usuario o a los controles básicos del sistema. Esto confirmó que el atacante utilizó la sesión de administrador para descargar directamente su carga útil desde un servidor externo.

---

## Fase 4: Persistencia Avanzada (Advanced Persistence)

Entendiendo la psicología del atacante, una cuenta de usuario alternativa no es suficiente garantía: si el servidor se reinicia o el equipo de SOC detecta al usuario `support`, el atacante pierde el acceso. Por lo tanto, el atacante necesita mecanismos que ejecuten su malware de forma automática sin depender de que un usuario inicie sesión. Para rastrear estos mecanismos invisibles, volví a auditar los registros del sistema.

En primer lugar, busqué la creación de servicios maliciosos filtrando por el **Event ID 4697** (instalación de un servicio en el sistema). Detecté la instalación de un servicio configurado con un nombre engañoso: `Data Protection Service`. Al examinar el campo *Service File Name*, descubrí que en realidad apuntaba a la ejecución del binario `nessus.exe`.

En segundo lugar, asumiendo que un atacante precavido establece capas de redundancia por si el servicio es descubierto y eliminado, investigué la creación de tareas programadas filtrando por el **Event ID 4698**. El hallazgo confirmó la redundancia: se creó la tarea programada `Amazon Sync`, cuya ruta de ejecución apuntaba al binario `troy.exe` alojado en `C:\Program Files\Common Files\troy.exe`. Ambas configuraciones le garantizaban al atacante la reconexión automática tras cualquier reinicio del sistema.

---

## Fase 5: Comando y Control (C2 - Command & Control)

En la fase final del análisis, mi objetivo fue verificar si los mecanismos de persistencia creados funcionaron tras un reinicio del sistema y cómo el malware establecía comunicación con el exterior. Para evaluar la actividad a nivel de procesos y red, volví a consultar los registros de `Sysmon`.

Para rastrear la ejecución del proceso, filtré por el **Event ID 1** de Sysmon (Process Creation) enfocado en el proceso padre `services.exe`. Verifiqué que, al arrancar el sistema operativo, `services.exe` levantó automáticamente el servicio falso `Data Protection Service`, iniciando el binario malicioso en segundo plano sin intervención humana.

Finalmente, para comprobar la salida hacia internet y la infraestructura del atacante, filtré por el **Event ID 22** de Sysmon (DNS Query). En el campo *QueryName*, identifiqué las peticiones de resolución de nombres DNS realizadas por el ejecutable malicioso buscando la IP de su servidor C2. Con este hallazgo se confirmó la apertura de un canal de comunicación bidireccional saliente, completando la investigación del ciclo de vida del ataque.









RESUMEN DE HALLAZGOS

## Fase 1: Acceso Inicial (Initial Access)

**Objetivo:** Identificar el vector de entrada utilizado por el atacante para comprometer el sistema[cite: 5, 6].  
**Fuente de datos:** `Security.evtx` (Windows Threat Detection 1)[cite: 5, 6]

* **Análisis de Fuerza Bruta:**  
  * **Event ID:** `4625` (An Account Failed to Log On)[cite: 5, 6].
  * **Comportamiento:** Ráfaga masiva y automatizada de intentos fallidos de inicio de sesión dirigidos secuencialmente contra la cuenta `Administrator`[cite: 5, 6].
  * **Frecuencia:** Eventos generados segundo a segundo, confirmando el uso de herramientas de ataque de diccionario[cite: 5, 6].

* **Consolidación del Acceso:**  
  * **Event ID:** `4624` (An Account Was Successfully Logged On)[cite: 5, 6].
  * **Fecha y Hora:** 20 de mayo de 2025, 09:51:48[cite: 5].
  * **Tipo de Inicio de Sesión (Logon Type):** `10` (Remote Interactive / RDP)[cite: 5, 6].
  * **Cuenta Compromedida:** `Administrator`[cite: 5, 6].
  * **Evidencia Técnica:** Establecimiento exitoso de sesión interactiva RDP. La dirección IP y el nombre del equipo de origen del atacante quedaron registrados en las secciones *Source Network Address* y *Workstation Name* del apartado *Network Information*[cite: 5].

---

## Fase 2: Persistencia Inicial y Elevación de Privilegios

**Objetivo:** Rastrear la creación de cuentas locales para mantener acceso secundario tras el compromiso RDP[cite: 6].  
**Fuente de datos:** `Security.evtx` (Windows Threat Detection 1)[cite: 6]

* **Creación de Cuenta Local:**  
  * **Event ID:** `4720` (A user account was created)[cite: 6].
  * **Detalle:** Desde la sesión activa RDP de `Administrator`, el atacante creó la cuenta local `support`[cite: 6].

* **Elevación de Privilegios:**  
  * **Event ID:** `4732` (A member was added to a security-enabled local group)[cite: 6].
  * **Detalle:** Asignación inmediata del usuario `support` al grupo local `Administrators`[cite: 6].
  * **Impacto:** Creación de una cuenta de respaldo legítima en apariencia con privilegios administrativos completos, diseñada para mitigar la pérdida de acceso en caso de revocación de credenciales de la cuenta `Administrator`[cite: 6].

---

## Fase 3: Entrega de Payload (Payload Delivery)

**Objetivo:** Identificar la descarga y almacenamiento de ejecutables maliciosos dentro del equipo comprometido[cite: 6].  
**Fuente de datos:** Registros de `Sysmon` (Windows Threat Detection 3)[cite: 6]

* **Detección de Archivo Malicioso:**  
  * **Event ID (Sysmon):** `11` (FileCreate / File Creation)[cite: 6].
  * **Nombre de Archivo Identificado:** `Urgent.inc.doc.Zone.Identifier`[cite: 6].
  * **Indicador de Compromiso (IOC):** Presencia de una estructura con doble extensión (`.inc.doc`), empleada para evadir inspecciones de usuario[cite: 6].
  * **Origen:** Descarga realizada dentro de la sesión interactiva del usuario administrador desde un servidor externo[cite: 6].

---

## Fase 4: Persistencia Avanzada (Advanced Persistence)

**Objetivo:** Documentar los mecanismos de ejecución automática configurados para resistir reinicios del sistema[cite: 6, 7].  
**Fuente de datos:** `Security.evtx` (Windows Threat Detection 3)[cite: 6, 7]

* **Mecanismo Primario: Servicio del Sistema Malicioso**  
  * **Event ID:** `4697` (A service was installed in the system)[cite: 6, 7].
  * **Nombre del Servicio:** `Data Protection Service`[cite: 6, 7].
  * **Ruta del Ejecutable (Service File Name):** Ejecución directa del archivo `nessus.exe`[cite: 7].
  * **Propósito:** Inicialización automática del binario malicioso al arrancar el sistema operativo sin necesidad de inicio de sesión interactivo[cite: 6, 7].

* **Mecanismo de Redundancia: Tarea Programada**  
  * **Event ID:** `4698` (A scheduled task was created)[cite: 6, 7].
  * **Nombre de la Tarea:** `Amazon Sync`[cite: 6, 7].
  * **Ruta de Ejecución:** `C:\Program Files\Common Files\troy.exe`[cite: 7].
  * **Análisis:** Enmascaramiento mediante una denominación comercial ficticia (`Amazon Sync`) para ejecutar de forma persistente el binario `troy.exe` alojado en directorios del sistema[cite: 6, 7].

---

## Fase 5: Comando y Control (C2 - Command & Control)

**Objetivo:** Verificar el levantamiento del proceso malicioso y la generación de tráfico de balizado hacia la infraestructura del atacante[cite: 7].  
**Fuente de datos:** Registros de `Sysmon` (Windows Threat Detection 3)[cite: 7]

* **Ejecución y Levantamiento de Proceso:**  
  * **Event ID (Sysmon):** `1` (Process Creation)[cite: 7].
  * **Proceso Padre (ParentImage):** `services.exe`[cite: 7].
  * **Comportamiento:** Tras el reinicio del servidor, el proceso padre `services.exe` activa automáticamente el servicio falso `Data Protection Service`, iniciando el binario malicioso en segundo plano[cite: 7].

* **Resolución DNS y Canal C2:**  
  * **Event ID (Sysmon):** `22` (DNSEvent - DNS query)[cite: 7].
  * **Análisis de Campo (QueryName):** Registro de peticiones de resolución de nombres DNS asociadas al binario persistente[cite: 7].
  * **Impacto:** Confirmación de la apertura de un canal de comunicación saliente bidireccional entre la máquina víctima y el servidor C2 del atacante para la recepción de comandos remotos[cite: 7].
