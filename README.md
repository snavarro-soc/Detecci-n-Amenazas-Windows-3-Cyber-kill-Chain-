# Detección de Amenazas en Windows 3: Cyber Kill Chain
**Análisis forense basado en el ciclo de vida del adversario.** Investigación respaldada en los laboratorios prácticos del módulo **Windows Threat Detection 3** de **TryHackMe**, evaluando la telemetría de `Sysmon.evtx` y `Security.evtx` para reconstruir la línea de tiempo de un ataque real.

# 🟢 INFORME SOC: DETECCIÓN DE AMENAZAS EN WINDOWS
## 🔵 Análisis Forense basado en el Ciclo de Vida del Adversario (Cyber Kill Chain)

- **ANALISTA RESPONSABLE:** Sebastián Navarro M.
- **ENTORNO EVALUADO:** TryHackMe - Windows Threat Detection 3
- **REGISTROS ANALIZADOS:** `Sysmon.evtx` & `Security.evtx`
---

### 🟢 1. Introducción y Contexto del Laboratorio
Como analista SOC, desarrollé este informe basándome en el entorno práctico del módulo **Windows Threat Detection 3 de TryHackMe**. El objetivo de este caso de estudio es demostrar la capacidad de analizar un incidente cibernético completo. En lugar de reportar eventos aislados, correlacioné cada hallazgo técnico con las fases de la **Cyber Kill Chain**, documentando paso a paso cómo el atacante logró entrar, qué herramientas descargó y cómo aseguró su control sobre la máquina.

### 🟢 2. Fase 1 y 2: Acceso Inicial y Entrega de Carga Útil (Initial Access & Delivery)
En esta fase inicial, investigué cómo el atacante logró romper el perímetro y qué hizo inmediatamente después de obtener acceso al sistema.

- 🔵 **Intrusión por Fuerza Bruta (Acceso Inicial):** Al analizar los registros de auditoría en `Security.evtx` y filtrar por el **`Event ID 4625`** (Logon Failure), detecté una ráfaga masiva de intentos de autenticación fallidos contra la cuenta `Administrator`. El atacante continuó este ataque de diccionario hasta lograr adivinar la credencial, consolidando su acceso interactivo por Escritorio Remoto (comprobable mediante el **`Event ID 4624`**, Tipo de inicio de sesión 10).
- 🔵 **Entrega del Payload (Delivery):** Una vez que el atacante estuvo dentro del sistema a través de RDP, procedió a descargar sus herramientas. Utilizando la telemetría de `Sysmon.evtx` y filtrando por el **`Event ID 11`** (File Created), identifiqué la creación del archivo `urgent_.zip` en la ruta `C:\Users\Administrator\Downloads\URGENT!\URGENT!`.

> **Contexto Forense:** El análisis del Alternate Data Stream `Zone.Identifier` en el archivo `.zip` confirmó que este provino de una descarga directa de Internet, materializando la entrega efectiva del código malicioso en el equipo comprometido.

### 🟢 3. Fase 3: Persistencia y Escalada de Privilegios (Persistence & Privilege Escalation)
Sabiendo que la contraseña comprometida del administrador podía ser cambiada por el equipo de TI y perderían el acceso, el atacante ejecutó acciones tácticas para asegurar una puerta trasera permanente.

- 🔵 **Creación de Cuenta Trampa:** Revisando `Security.evtx` mediante el **`Event ID 4720`**, detecté la creación manual de un usuario local llamado `support`. 
- 🔵 **Escalada de Privilegios:** Inmediatamente después de crear la cuenta, el registro arrojó el **`Event ID 4732`** (Security-enabled local group modification). Esto demostró que el atacante agregó manualmente al usuario `support` al grupo `Administrators`, garantizándole permisos de nivel de sistema y acceso RDP sin depender de la cuenta original.

### 🟢 4. Fase 4: Persistencia Avanzada (Installation & Persistence)
Para asegurar que el malware se ejecutara de forma automática y silenciosa en cada reinicio del servidor sin intervención humana, el atacante utilizó dos métodos de evasión:

- 🔵 **Abuso de Servicios del Sistema:** El atacante utilizó `sc.exe` para registrar un servicio malicioso. Al revisar el **`Event ID 4697`**, evidencié que el binario `C:\malware.exe` fue instalado camuflándose bajo el nombre legítimo de `Data Protection Service`.
- 🔵 **Tareas Programadas Engañosas:** También se programó la ejecución del malware `troy.exe`. Analizando el contenido XML de la tarea en el **`Event ID 4698`**, detecté que el binario ubicado en `C:\Program Files\Common Files\troy.exe` se registró utilizando el nombre engañoso `\AmazonSync`.

> **Correlación de Procesos:** En los registros de creación de procesos comprobé que el gestor legítimo `services.exe` fue manipulado para ejecutar `svchost.exe` con los parámetros `-k netsvcs -ps Schedule`, lanzando el malware silenciosamente durante el proceso de arranque.

### 🟢 5. Fase 5: Comando y Control (Command and Control)
El objetivo final de toda esta persistencia era mantener comunicación constante con la infraestructura del atacante (Servidor C2).

- 🔵 **Conexión C2:** A partir del payload secundario `update.exe`, el malware estableció la baliza de comunicación. Utilizando `Sysmon.evtx` y filtrando por el **`Event ID 22`** (DNSEvent), detecté las resoluciones y consultas DNS dirigidas al dominio malicioso `route.m365officesync.workers.dev`.
- 🔵 **Validación Forense:** Al probar el comportamiento de `troy.exe` en el entorno del laboratorio, identifiqué que requería su comando padre original para ejecutarse. A través del **`Event ID 1`** (Process Creation) de Sysmon, extraje el ParentCommandLine exacto necesario para su análisis: `C:\Windows\system32\svchost.exe -k netsvcs -ps Schedule`. 

### 🟢 6. Resumen de Indicadores de Compromiso (IoCs)
Tabla de referencias cruzadas con los artefactos técnicos y registros auditados a lo largo del caso:

| Fase Kill Chain | Artefacto / Indicador Técnico (IoC) | Origen y Event ID |
| :--- | :--- | :--- |
| **Initial Access** | Ráfaga de fuerza bruta y acceso RDP exitoso | `Security.evtx` - 🟣 **`ID 4625 / 4624`** |
| **Delivery** | Archivo `urgent_.zip` con flujo ADS `Zone.Identifier` | `Sysmon.evtx` - 🟣 **`ID 11`** |
| **Execution** | Payload secundario en `AppData\Roaming\update.exe` | `Sysmon.evtx` - 🟣 **`ID 1/11`** |
| **Persistence** | Creación cuenta `support` y asignación a Administrators | `Security.evtx` - 🟣 **`ID 4720/4732`** |
| **Persistence** | Servicio falso Data Protection Service (`malware.exe`) | `Security.evtx` - 🟣 **`ID 4697`** |
| **Persistence** | Tarea programada `\AmazonSync` (`troy.exe`) | `Security.evtx` - 🟣 **`ID 4698`** |
| **C2/Exfil** | Dominio C2 `route.m365officesync.workers.dev` | `Sysmon.evtx` - 🟣 **`ID 22`** |

### 🟢 7. Cierre del Informe Forense
La elaboración de este informe en el entorno de TryHackMe refleja mi capacidad técnica para realizar triaje de eventos de seguridad en sistemas Windows. Destaca la importancia de no aislar los hallazgos individuales, sino comprender y documentar la estrategia y mentalidad del adversario a través de las fases completas del Cyber Kill Chain.
