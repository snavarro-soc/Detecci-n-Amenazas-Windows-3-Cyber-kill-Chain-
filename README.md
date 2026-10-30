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
## 🔴 Fase 1: Acceso Inicial (Initial Access)

### Análisis Narrativo y Razonamiento
En esta primera fase investigué cómo el atacante logró romper el perímetro de autenticación del servidor[cite: 5, 6]. Al revisar los registros de auditoría en <font color="#00FF66"><b>Security.evtx</b></font> (telemetría de Windows Threat Detection 1)[cite: 5, 6], mi primer razonamiento fue buscar signos de un intento de intrusión por la fuerza[cite: 5, 6]. Para corroborar esta hipótesis, filtré por el <font color="#00FF66"><b>Event ID 4625</b></font> (inicio de sesión fallido)[cite: 5, 6].

El resultado reveló una ráfaga masiva y constante de autenticaciones fallidas dirigidas contra la cuenta <font color="#00FF66"><b>Administrator</b></font>[cite: 5, 6]. La frecuencia de estos eventos (registrados segundo a segundo) confirmó de inmediato el uso de una herramienta automatizada ejecutando un ataque de diccionario[cite: 5, 6].

Sabiendo que un atacante no se detiene en los intentos fallidos, la duda lógica que surgió fue: *¿logró adivinar la credencial?* Para responder a esto, cambié el filtro al <font color="#00FF66"><b>Event ID 4624</b></font> (inicio de sesión exitoso)[cite: 5, 6]. Al analizar los eventos posteriores a la ráfaga, confirmé que el 20 de mayo de 2025 a las 09:51:48 se consolidó la intrusión con un acceso exitoso a la cuenta <font color="#00FF66"><b>Administrator</b></font>[cite: 5]. Al inspeccionar el detalle técnico, identifiqué un <font color="#00FF66"><b>Logon Type 10</b></font>, lo que demostró que el acceso se realizó de forma interactiva y remota a través de RDP[cite: 5, 6]. En la sección *Network Information* (campos *Source Network Address* y *Workstation Name*), registré la dirección IP y el nombre del equipo utilizado por el atacante para penetrar el sistema[cite: 5].

### Ficha Técnica de Hallazgos
* **Objetivo:** Identificar el vector de entrada y confirmar el compromiso del servidor[cite: 5, 6].
* **Fuente de datos:** <font color="#00FF66"><b>Security.evtx</b></font> (Windows Threat Detection 1)[cite: 5, 6].
* **Análisis de Fuerza Bruta:**
  * **Event ID:** <font color="#00FF66"><b>4625</b></font> (An Account Failed to Log On)[cite: 5, 6].
  * **Comportamiento:** Ráfaga masiva y automatizada contra la cuenta <font color="#00FF66"><b>Administrator</b></font>[cite: 5, 6].
  * **Frecuencia:** Intentos fallidos segundo a segundo (ataque de diccionario)[cite: 5, 6].
* **Consolidación de Acceso:**
  * **Event ID:** <font color="#00FF66"><b>4624</b></font> (An Account Was Successfully Logged On)[cite: 5, 6].
  * **Fecha y Hora:** 20/05/2025 a las 09:51:48[cite: 5].
  * **Tipo de Inicio de Sesión:** <font color="#00FF66"><b>Logon Type 10</b></font> (Remote Interactive / RDP)[cite: 5, 6].
  * **Cuenta Compromedida:** <font color="#00FF66"><b>Administrator</b></font>[cite: 5, 6].
  * **Evidencia Técnica:** Dirección IP de origen y nombre del equipo atacante registrados en el apartado *Network Information* (*Source Network Address* y *Workstation Name*)[cite: 5].

---

## 🔴 Fase 2: Persistencia Inicial y Elevación de Privilegios

### Análisis Narrativo y Razonamiento
Una vez que el atacante estuvo dentro del sistema mediante RDP con la cuenta <font color="#00FF66"><b>Administrator</b></font>, su siguiente movimiento lógico era asegurar una vía de acceso secundaria[cite: 6]. Como analista, sé que los atacantes prevén que la contraseña del administrador principal pueda ser cambiada o su sesión revocada[cite: 6]. Por lo tanto, mi hipótesis fue que el atacante crearía una cuenta local de respaldo durante esa misma sesión interactiva[cite: 6].

Para verificar esta sospecha, filtré en <font color="#00FF66"><b>Security.evtx</b></font> por el <font color="#00FF66"><b>Event ID 4720</b></font> (creación de cuenta de usuario)[cite: 6]. La búsqueda confirmó la hipótesis: desde la sesión RDP activa de <font color="#00FF66"><b>Administrator</b></font> se creó la cuenta de usuario local <font color="#00FF66"><b>support</b></font>[cite: 6]. 

Sin embargo, una cuenta estándar no le serviría de mucho para controlar el servidor. El siguiente paso del atacante tenía que ser otorgarle privilegios totales[cite: 6]. Para auditar este movimiento, filtré por el <font color="#00FF66"><b>Event ID 4732</b></font> (incorporación de un miembro a un grupo local de seguridad)[cite: 6]. Ahí descubrí que la cuenta <font color="#00FF66"><b>support</b></font> fue agregada inmediatamente al grupo <font color="#00FF66"><b>Administrators</b></font>[cite: 6]. Con esto, el atacante dejó configurada una puerta trasera interactiva legítima en apariencia para reconectarse cuando lo deseara[cite: 6].

### Ficha Técnica de Hallazgos
* **Objetivo:** Rastrear la creación de cuentas locales de respaldo para mantener acceso secundario[cite: 6].
* **Fuente de datos:** <font color="#00FF66"><b>Security.evtx</b></font> (Windows Threat Detection 1)[cite: 6].
* **Creación de Cuenta Local:**
  * **Event ID:** <font color="#00FF66"><b>4720</b></font> (A user account was created)[cite: 6].
  * **Cuenta Creada:** <font color="#00FF66"><b>support</b></font>[cite: 6].
  * **Origen:** Sesión activa de RDP bajo la cuenta <font color="#00FF66"><b>Administrator</b></font>[cite: 6].
* **Elevación de Privilegios:**
  * **Event ID:** <font color="#00FF66"><b>4732</b></font> (A member was added to a security-enabled local group)[cite: 6].
  * **Grupo Destino:** <font color="#00FF66"><b>Administrators</b></font>[cite: 6].
  * **Impacto:** Otorgamiento de privilegios administrativos completos a la nueva cuenta <font color="#00FF66"><b>support</b></font>[cite: 6].

---

## 🔴 Fase 3: Entrega de Carga Útil (Payload Delivery)

### Análisis Narrativo y Razonamiento
Con la persistencia de usuario garantizada, la investigación debía determinar qué herramientas o malware ingresó el atacante al servidor para comenzar a operar[cite: 6]. Para este análisis de comportamiento en la máquina, correlacioné la línea de tiempo cambiando a la telemetría de <font color="#00FF66"><b>Sysmon</b></font> en el laboratorio Windows Threat Detection 3[cite: 6].

Mi razonamiento analítico consistió en buscar la creación de archivos sospechosos en el sistema generados durante la ventana temporal de la sesión activa del atacante[cite: 6]. Al filtrar por el <font color="#00FF66"><b>Event ID 11</b></font> de Sysmon (File Creation), identifiqué la descarga y creación del archivo <font color="#00FF66"><b>Urgent.inc.doc.Zone.Identifier</b></font>[cite: 6]. 

La estructura del nombre presentó de inmediato una anomalía: el uso de una doble extensión (<font color="#00FF66"><b>.inc.doc</b></font>), una técnica clásica de evasión para engañar al usuario o a los controles básicos del sistema[cite: 6]. Esto confirmó que el atacante utilizó la sesión de administrador para descargar directamente su carga útil desde un servidor externo[cite: 6].

### Ficha Técnica de Hallazgos
* **Objetivo:** Identificar la descarga e inoculación de ejecutable malicioso dentro del sistema[cite: 6].
* **Fuente de datos:** Registros de <font color="#00FF66"><b>Sysmon</b></font> (Windows Threat Detection 3)[cite: 6].
* **Detección de Archivo Malicioso:**
  * **Event ID (Sysmon):** <font color="#00FF66"><b>11</b></font> (FileCreate / File Creation)[cite: 6].
  * **Nombre de Archivo:** <font color="#00FF66"><b>Urgent.inc.doc.Zone.Identifier</b></font>[cite: 6].
  * **Indicador de Compromiso (IOC):** Estructura de nombre con doble extensión (<font color="#00FF66"><b>.inc.doc</b></font>)[cite: 6].
  * **Mecanismo:** Descarga directa desde servidor externo durante la sesión activa de administrador[cite: 6].

---

## 🔴 Fase 4: Persistencia Avanzada (Advanced Persistence)

### Análisis Narrativo y Razonamiento
Entendiendo la psicología del atacante, una cuenta de usuario alternativa no es suficiente garantía: si el servidor se reinicia o el equipo de SOC detecta al usuario <font color="#00FF66"><b>support</b></font>, el atacante pierde el acceso[cite: 6]. Por lo tanto, el atacante necesita mecanismos que ejecuten su malware de forma automática sin depender de que un usuario inicie sesión[cite: 6]. Para rastrear estos mecanismos invisibles, volví a auditar los registros del sistema en <font color="#00FF66"><b>Security.evtx</b></font>[cite: 6, 7].

En primer lugar, busqué la creación de servicios maliciosos filtrando por el <font color="#00FF66"><b>Event ID 4697</b></font> (instalación de un servicio en el sistema)[cite: 6, 7]. Detecté la instalación de un servicio configurado con un nombre engañoso: <font color="#00FF66"><b>Data Protection Service</b></font>[cite: 6, 7]. Al examinar el campo *Service File Name*, descubrí que en realidad apuntaba a la ejecución del binario <font color="#00FF66"><b>nessus.exe</b></font>[cite: 7].

En segundo lugar, asumiendo que un atacante precavido establece capas de redundancia por si el servicio es descubierto y eliminado, investigué la creación de tareas programadas filtrando por el <font color="#00FF66"><b>Event ID 4698</b></font>[cite: 6, 7]. El hallazgo confirmó la redundancia: se creó la tarea programada <font color="#00FF66"><b>Amazon Sync</b></font>, cuya ruta de ejecución apuntaba al binario <font color="#00FF66"><b>troy.exe</b></font> alojado en <font color="#00FF66"><b>C:\Program Files\Common Files\troy.exe</b></font>[cite: 6, 7]. Ambas configuraciones le garantizaban al atacante la reconexión automática tras cualquier reinicio del sistema[cite: 6, 7].

### Ficha Técnica de Hallazgos
* **Objetivo:** Documentar mecanismos de ejecución automática del malware resistentes a reinicios[cite: 6, 7].
* **Fuente de datos:** <font color="#00FF66"><b>Security.evtx</b></font> (Windows Threat Detection 3)[cite: 6, 7].
* **Mecanismo Primario (Servicio Malicioso):**
  * **Event ID:** <font color="#00FF66"><b>4697</b></font> (A service was installed in the system)[cite: 6, 7].
  * **Nombre del Servicio:** <font color="#00FF66"><b>Data Protection Service</b></font>[cite: 6, 7].
  * **Ruta del Ejecutable (*Service File Name*):** <font color="#00FF66"><b>nessus.exe</b></font>[cite: 7].
* **Mecanismo Redundante (Tarea Programada):**
  * **Event ID:** <font color="#00FF66"><b>4698</b></font> (A scheduled task was created)[cite: 6, 7].
  * **Nombre de la Tarea:** <font color="#00FF66"><b>Amazon Sync</b></font>[cite: 6, 7].
  * **Ruta del Ejecutable:** <font color="#00FF66"><b>C:\Program Files\Common Files\troy.exe</b></font>[cite: 7].

---

## 🔵 Fase 5: Comando y Control (C2 - Command & Control)

### Análisis Narrativo y Razonamiento
En esta fase del análisis, mi objetivo fue verificar si los mecanismos de persistencia creados funcionaron tras un reinicio del sistema y cómo el malware establecía comunicación con el exterior[cite: 7]. Para evaluar la actividad a nivel de procesos y red, volví a consultar los registros de <font color="#00FF66"><b>Sysmon</b></font>[cite: 7].

Para rastrear la ejecución del proceso, filtré por el <font color="#00FF66"><b>Event ID 1</b></font> de Sysmon (Process Creation) enfocado en el proceso padre <font color="#00FF66"><b>services.exe</b></font>[cite: 7]. Verifiqué que, al arrancar el sistema operativo, <font color="#00FF66"><b>services.exe</b></font> levantó automáticamente el servicio falso <font color="#00FF66"><b>Data Protection Service</b></font>, iniciando el binario malicioso en segundo plano sin intervención humana[cite: 7].

Finalmente, para comprobar la salida hacia internet y la infraestructura del atacante, filtré por el <font color="#00FF66"><b>Event ID 22</b></font> de Sysmon (DNS Query)[cite: 7]. En el campo *QueryName*, identifiqué las peticiones de resolución de nombres DNS realizadas por el ejecutable malicioso buscando la IP de su servidor C2[cite: 7]. Con este hallazgo se confirmó la apertura de un canal de comunicación bidireccional saliente, completando la investigación técnica de la secuencia del ataque[cite: 7].

### Ficha Técnica de Hallazgos
* **Objetivo:** Confirmar la activación automática del malware post-reinicio y la generación de tráfico C2[cite: 7].
* **Fuente de datos:** Registros de <font color="#00FF66"><b>Sysmon</b></font> (Windows Threat Detection 3)[cite: 7].
* **Ejecución de Proceso:**
  * **Event ID (Sysmon):** <font color="#00FF66"><b>1</b></font> (Process Creation)[cite: 7].
  * **Proceso Padre (*ParentImage*):** <font color="#00FF66"><b>services.exe</b></font>[cite: 7].
  * **Comportamiento:** Activación automática del binario malicioso por parte de <font color="#00FF66"><b>services.exe</b></font> mediante el servicio <font color="#00FF66"><b>Data Protection Service</b></font>[cite: 7].
* **Canal de Comunicación C2:**
  * **Event ID (Sysmon):** <font color="#00FF66"><b>22</b></font> (DNSEvent - DNS query)[cite: 7].
  * **Campo Clave (*QueryName*):** Petición de resolución DNS generada por el proceso persistente hacia la infraestructura externa del atacante[cite: 7].

---

## 🔵 Fase 6: Resumen de Indicadores de Compromiso (IOCs)

### Consolidados de la Investigación Forense
Para facilitar las tareas de monitoreo, bloqueo y cacería de amenazas (Threat Hunting) por parte del equipo de respuesta a incidentes, se consolidan todos los Indicadores de Compromiso (IOCs) extraídos durante el análisis:

* **Archivos y Cargas Útiles Maliciosas:**
  * <font color="#00FF66"><b>Urgent.inc.doc.Zone.Identifier</b></font> (Payload inicial con técnica de doble extensión)[cite: 6].
  * <font color="#00FF66"><b>nessus.exe</b></font> (Binario malicioso enmascarado como herramienta de escaneo y vinculado al servicio falso)[cite: 7].
  * <font color="#00FF66"><b>C:\Program Files\Common Files\troy.exe</b></font> (Binario persistente vinculado a la tarea programada redundante)[cite: 7].

* **Cuentas de Usuario y Credenciales:**
  * <font color="#00FF66"><b>Administrator</b></font> (Cuenta legítima comprometida mediante ataque de fuerza bruta RDP)[cite: 5, 6].
  * <font color="#00FF66"><b>support</b></font> (Cuenta de usuario ilegítima creada por el atacante e integrada al grupo <font color="#00FF66"><b>Administrators</b></font>)[cite: 6].

* **Artefactos de Persistencia en Sistema:**
  * Servicio del Sistema: <font color="#00FF66"><b>Data Protection Service</b></font>[cite: 6, 7].
  * Tarea Programada: <font color="#00FF66"><b>Amazon Sync</b></font>[cite: 6, 7].

* **Red y Comunicaciones C2:**
  * Registros de peticiones DNS salientes vinculadas al <font color="#00FF66"><b>Event ID 22</b></font> de Sysmon asociadas a la infraestructura C2 del atacante[cite: 7].
  * Conexiones entrantes mediante <font color="#00FF66"><b>Logon Type 10</b></font> desde dirección IP remota de origen registrada en el <font color="#00FF66"><b>Event ID 4624</b></font>[cite: 5, 6].

---

## 🟢 Fase 7: Remediación, Mitigación y Cierre Forense

### Acciones de Erradicación Inmediata
1. **Aislamiento de Red:** Desconectar inmediatamente la máquina afectada de la red corporativa para contener el tráfico de comunicación hacia la infraestructura C2 y prevenir un movimiento lateral.
2. **Depuración de Cuentas:** 
   * Forzar el restablecimiento inmediato de credenciales para la cuenta <font color="#00FF66"><b>Administrator</b></font> e implementar complejidad estricta.
   * Eliminar de forma definitiva la cuenta local no autorizada <font color="#00FF66"><b>support</b></font> y revocar sus privilegios administrativos.
3. **Eliminación de Artefactos Maliciosos:**
   * Detener y desinstalar el servicio falso <font color="#00FF66"><b>Data Protection Service</b></font> y purgar el ejecutable <font color="#00FF66"><b>nessus.exe</b></font>[cite: 6, 7].
   * Eliminar la tarea programada <font color="#00FF66"><b>Amazon Sync</b></font> y remover el binario <font color="#00FF66"><b>C:\Program Files\Common Files\troy.exe</b></font> del disco de forma segura[cite: 6, 7].

### Recomendaciones de Mitigación y Fortalecimiento (Hardening)
* **Protección del Perímetro RDP:** Deshabilitar la exposición directa del puerto 3389 (RDP) a Internet. Implementar una solución de VPN corporativa con Autenticación de Doble Factor (MFA) obligatoria para todo acceso remoto.
* **Políticas de Bloqueo de Cuentas:** Configurar políticas de bloqueo (*Account Lockout Policy*) en Windows para inhabilitar automáticamente cuentas de usuario tras 3 a 5 intentos fallidos consecutivos de inicio de sesión, neutralizando ataques de diccionario automatizados.
* **Monitoreo y Reglas de Alerta en SIEM:** Crear reglas de detección automatizadas para auditar en tiempo real la creación de nuevos servicios (<font color="#00FF66"><b>Event ID 4697</b></font>)[cite: 6, 7], tareas programadas (<font color="#00FF66"><b>Event ID 4698</b></font>)[cite: 6, 7] y adición de usuarios a grupos privilegiados (<font color="#00FF66"><b>Event ID 4732</b></font>)[cite: 6].






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
