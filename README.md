# Deteccion-Amenazas-Windows-3-Cyber-kill-Chain-
Análisis forense de detección de amenazas basado en el ciclo de vida del adversario (Cyber Kill Chain). Investigación respaldada en los laboratorios prácticos del módulo Windows Threat Detection 3 de TryHackMe, evaluando los artefactos Sysmon.evtx y Security.evtx para reconstruir el ataque.

**INFORME SOC: DETECCIÓN DE AMENAZAS EN WINDOWS**
**Análisis Forense basado en el Ciclo de Vida del Adversario (Cyber Kill Chain)**

**ANALISTA RESPONSABLE:** Sebastián Navarro M.
**ENTORNO EVALUADO:** TryHackMe - Windows Threat Detection 3
**ARTEFACTOS ANALIZADOS:** `Sysmon.evtx` & `Security.evtx`

---

**1. Introducción y Contexto del Laboratorio**
Como analista SOC de nivel 1, trabajé este caso práctico en TryHackMe para analizar un incidente real de principio a fin en Windows. En lugar de ver los eventos como registros aislados, mapeé cada hallazgo dentro de la Cyber Kill Chain para entender los pasos del atacante.

El objetivo de esta investigación fue reconstruir la línea de tiempo del ataque: desde los primeros intentos de acceso y descarga de malware, pasando por la creación de cuentas falsas, hasta establecer persistencia mediante servicios y tareas programadas para conectar con el servidor de Comando y Control (C2).

**2. Fase 1: Acceso Inicial y Entrega (Initial Access & Delivery)**
En esta fase, el atacante intentó romper el perímetro de autenticación. Mi tarea fue determinar cómo vulneró el sistema y qué usó para descargar el malware.

* **Intentos de Fuerza Bruta:** Al revisar el registro `Security.evtx` filtrando por el `Event ID 4625` (Logon Failure), rastreé los intentos de autenticación contra la cuenta `Administrator`. Observé que el atacante falló 6 veces antes de cambiar su estrategia.
* **Entrega del Payload (Delivery):** Al fallar por fuerza bruta, recurrió a la descarga de un archivo. En `Sysmon.evtx` (`Event ID 11` - FileCreated), identifiqué la descarga del archivo `urgent_.zip` en la ruta `C:\Users\Administrator\Downloads\URGENT!\URGENT!`, con el flujo `Zone.Identifier`.

**Contexto:** El Alternate Data Stream `Zone.Identifier` confirma que el archivo provino de una descarga de Internet, marcando el inicio de la entrega del exploit.

**3. Fase 2: Persistencia y Escalada de Privilegios (Persistence & Privilege Escalation)**
Como el acceso inicial puede perderse si se cambian las contraseñas, el atacante pasó a asegurar su persistencia.

* **Creación de Cuenta (Event ID 4720):** Para tener una puerta trasera, el atacante creó un usuario local por consola. En `Security.evtx` (ID `4720`), localicé la creación de la cuenta `support`. Es común que usen nombres de departamentos de soporte para pasar desapercibidos en revisiones visuales.
* **Escalada de Privilegios (Event ID 4732):** Inmediatamente después, detecté el evento `4732` (Security-enabled local group modification). Esto confirmó que el usuario `support` fue agregado de forma manual al grupo local `Administrators` para obtener permisos de escritorio remoto (RDP).

**4. Fase 3: Persistencia Avanzada (Installation & Persistence)**
Para asegurar que el malware se ejecute automáticamente en cada reinicio sin intervención humana, el atacante usó dos métodos:

* **Abuso de Servicios (Event ID 4697):** Utilizó `sc.exe` para registrar un servicio. Al revisar el evento `4697`, vi que el binario `C:\malware.exe` se camufló bajo el nombre `Data Protection Service`, simulando ser una función legítima de Windows.
* **Tareas Programadas (Event ID 4698):** También programó la ejecución del malware `troy.exe`. Al analizar el contenido XML de la tarea en el evento `4698`, detecté que el binario en `C:\Program Files\Common Files\troy.exe` se registró con el nombre engañoso `\AmazonSync`.

**Correlación de Procesos:** En los logs comprobé que el gestor legítimo `services.exe` ejecutó `svchost.exe` con los parámetros `-k netsvcs -ps Schedule` para lanzar el malware silenciosamente durante el arranque.

**5. Fase 4: Comando y Control (Command & Control)**
El objetivo final de la persistencia era mantener conexión con el servidor C2. En esta fase, correlacioné la actividad de red y los procesos ejecutados.

* **Conexión C2:** A partir del payload `update.exe` (en `C:\Users\Administrator\AppData\Roaming\update.exe`), el malware estableció comunicación. Con `Sysmon.evtx` (`Event ID 22` - DNSEvent), detecté las consultas DNS hacia el dominio `route.m365officesync.workers.dev`, alojado en Cloudflare Workers para evadir bloqueos simulando tráfico de Microsoft.
* **Validación Forense:** Al probar `troy.exe` en el laboratorio, necesitaba el comando padre original para ejecutarse. Del evento `Event ID 1` de Sysmon saqué el ParentCommandLine exacto: `C:\Windows\system32\svchost.exe -k netsvcs -ps Schedule`. Al ingresarlo, obtuve la flag del caso: `THM{c2_is_on_schedule!}`.

**Conclusión:**
Este caso demuestra cómo se combinan distintas capas de persistencia (cuentas, servicios falsos y tareas) para evadir defensas. La clave del análisis SOC fue correlacionar la telemetría de Sysmon con los logs de Security de Windows.

**6. Resumen de Indicadores de Compromiso (IoCs)**
Tabla de referencias cruzadas con los artefactos técnicos y registros auditados:

| Fase Kill Chain | Artefacto / Indicador Técnico (IoC) | Origen y Event ID |
| :--- | :--- | :--- |
| **Initial Access** | 6 intentos fallidos contra cuenta Administrator | `Security.evtx` - `Event ID 4625` |
| **Delivery** | Archivo `urgent_.zip` con flujo ADS `Zone.Identifier` | `Sysmon.evtx` - `Event ID 11` |
| **Execution** | Payload secundario en `AppData\Roaming\update.exe` | `Sysmon.evtx` - `Event ID 1` / `ID 11` |
| **Persistence** | Creación cuenta `support` y grupo Administrators | `Security.evtx` - `Event ID 4720` / `4732` |
| **Persistence** | Servicio falso Data Protection Service (`malware.exe`) | `Security.evtx` - `Event ID 4697` |
| **Persistence** | Tarea programada `\AmazonSync` (`troy.exe`) | `Security.evtx` - `Event ID 4698` |
| **C2/Exfil** | Dominio C2 `route.m365officesync.workers.dev` | `Sysmon.evtx` - `Event ID 22` |
