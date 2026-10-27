# Deteccion-Amenazas-Windows-3-Cyber-kill-Chain-
Análisis forense de detección de amenazas basado en el ciclo de vida del adversario (Cyber Kill Chain). Investigación respaldada en los laboratorios prácticos del módulo Windows Threat Detection 3 de TryHackMe, evaluando los artefactos Sysmon.evtx y Security.evtx para reconstruir el ataque.
# 🟢 INFORME SOC: DETECCIÓN DE AMENAZAS EN WINDOWS
## 🔵 Análisis Forense basado en el Ciclo de Vida del Adversario (Cyber Kill Chain)

* **ANALISTA RESPONSABLE:** Sebastián Navarro M.
* **ENTORNO EVALUADO:** TryHackMe - Windows Threat Detection 3
* **ARTEFACTOS ANALIZADOS:** `Sysmon.evtx` & `Security.evtx`
---

### 🟢 1. Introducción y Contexto del Laboratorio
Como analista SOC de nivel 1, trabajé este caso práctico en TryHackMe para analizar un incidente real de principio a fin en Windows. En lugar de ver los eventos como registros aislados, mapeé cada hallazgo dentro de la Cyber Kill Chain para entender los pasos del atacante.

### 🟢 2. Fase 1: Acceso Inicial y Entrega (Initial Access and Delivery)
En esta fase, el atacante intentó romper el perímetro de autenticación. Mi tarea fue determinar cómo vulneró el sistema y qué usó para descargar el malware.

* 🔵 **Intentos de Fuerza Bruta:** Al revisar el registro `Security.evtx` filtrando por el **`Event ID 4625`** (Logon Failure), rastreé los intentos de autenticación contra la cuenta `Administrator`. Observé que el atacante falló 6 veces antes de cambiar su estrategia.
* 🔵 **Entrega del Payload (Delivery):** Al fallar por fuerza bruta, recurrió a la descarga de un archivo. En `Sysmon.evtx` (**`Event ID 11`** - FileCreated), identifiqué la descarga del archivo `urgent_.zip` en la ruta `C:\Users\Administrator\Downloads\URGENT!\URGENT!`, con el flujo `Zone.Identifier`.

> **Contexto:** El Alternate Data Stream `Zone.Identifier` confirma que el archivo provino de una descarga de Internet, marcando el inicio de la entrega del exploit.

### 🟢 3. Fase 2: Persistencia y Escalada de Privilegios (Persistence and Privilege Escalation)
Como el acceso inicial puede perderse si se cambian las contraseñas, el atacante pasó a asegurar su persistencia.

* 🔵 **Creación de Cuenta:** Para tener una puerta trasera, el atacante creó un usuario local por consola. En `Security.evtx` (**`Event ID 4720`**), localicé la creación de la cuenta `support`. 
* 🔵 **Escalada de Privilegios:** Inmediatamente después, detecté el **`Event ID 4732`** (Security-enabled local group modification). Esto confirmó que el usuario `support` fue agregado de forma manual al grupo local `Administrators` para obtener permisos de escritorio remoto (RDP).

### 🟢 4. Fase 3: Persistencia Avanzada (Installation and Persistence)
Para asegurar que el malware se ejecute automáticamente en cada reinicio sin intervención humana, el atacante usó dos métodos:

* 🔵 **Abuso de Servicios:** Utilizó `sc.exe` para registrar un servicio. Al revisar el **`Event ID 4697`**, vi que el binario `C:\malware.exe` se camufló bajo el nombre `Data Protection Service`.
* 🔵 **Tareas Programadas:** También programó la ejecución del malware `troy.exe`. Al analizar el contenido XML de la tarea en el **`Event ID 4698`**, detecté que el binario en `C:\Program Files\Common Files\troy.exe` se registró con el nombre engañoso `\AmazonSync`.

> **Correlación de Procesos:** En los logs comprobé que el gestor legítimo `services.exe` ejecutó `svchost.exe` con los parámetros `-k netsvcs -ps Schedule` para lanzar el malware silenciosamente durante el arranque.

### 🟢 5. Fase 4: Comando y Control (Command and Control)
El objetivo final de la persistencia era mantener conexión con el servidor C2. En esta fase, correlacioné la actividad de red y los procesos ejecutados.

* 🔵 **Conexión C2:** A partir del payload `update.exe`, el malware estableció comunicación. Con `Sysmon.evtx` (**`Event ID 22`** - DNSEvent), detecté las consultas DNS hacia el dominio `route.m365officesync.workers.dev`.
* 🔵 **Validación Forense:** Al probar `troy.exe` en el laboratorio, necesitaba el comando padre original para ejecutarse. Del **`Event ID 1`** de Sysmon saqué el ParentCommandLine exacto: `C:\Windows\system32\svchost.exe -k netsvcs -ps Schedule`. 

### 🟢 6. Resumen de Indicadores de Compromiso (IoCs)
Tabla de referencias cruzadas con los artefactos técnicos y registros auditados:

| Fase Kill Chain | Artefacto / Indicador Técnico (IoC) | Origen y Event ID |
| :--- | :--- | :--- |
| **Initial Access** | 6 intentos fallidos contra cuenta Administrator | `Security.evtx` - 🟣 **`ID 4625`** |
| **Delivery** | Archivo `urgent_.zip` con flujo ADS `Zone.Identifier` | `Sysmon.evtx` - 🟣 **`ID 11`** |
| **Execution** | Payload secundario en `AppData\Roaming\update.exe` | `Sysmon.evtx` - 🟣 **`ID 1/11`** |
| **Persistence** | Creación cuenta `support` y grupo Administrators | `Security.evtx` - 🟣 **`ID 4720/4732`** |
| **Persistence** | Servicio falso Data Protection Service (`malware.exe`) | `Security.evtx` - 🟣 **`ID 4697`** |
| **Persistence** | Tarea programada `\AmazonSync` (`troy.exe`) | `Security.evtx` - 🟣 **`ID 4698`** |
| **C2/Exfil** | Dominio C2 `route.m365officesync.workers.dev` | `Sysmon.evtx` - 🟣 **`ID 22`** |

### 🟢 7. Cierre del Informe Forense
La elaboración de este informe refleja mi competencia técnica en el triaje de eventos de seguridad en sistemas Windows, destacando la importancia de no aislar los hallazgos individuales, sino comprender la mentalidad del adversario a través de las fases del Cyber Kill Chain.
