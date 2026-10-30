# Detección de Amenazas en Windows 3: Cyber Kill Chain
**Análisis forense basado en el ciclo de vida del adversario.** Investigación respaldada en los laboratorios prácticos del módulo **Windows Threat Detection 3** de **TryHackMe**, evaluando la telemetría de `Sysmon.evtx` y `Security.evtx` para reconstruir la línea de tiempo de un ataque real.
# Detección de Amenazas en Windows 3: Cyber Kill Chain

Análisis forense basado en el ciclo de vida del adversario. Investigación respaldada en los laboratorios prácticos del módulo **Windows Threat Detection 3** de TryHackMe, evaluando la telemetría de `Sysmon.evtx` y `Security.evtx` para reconstruir la línea de tiempo de un ataque real.

---

## 🟢 INFORME SOC: DETECCIÓN DE AMENAZAS EN WINDOWS
### 🔵 Análisis Forense basado en el Ciclo de Vida del Adversario (Cyber Kill Chain)

* **ANALISTA RESPONSABLE:** Sebastián Navarro M.
* **ENTORNO EVALUADO:** TryHackMe - Windows Threat Detection 3
* **REGISTROS ANALIZADOS:** `Sysmon.evtx` & `Security.evtx`

---

## 🟢 Introducción y Contexto del Laboratorio

Como analista SOC, desarrollé este informe basándome en el entorno práctico del módulo *Windows Threat Detection 3* de TryHackMe. El objetivo de este caso de estudio es demostrar la capacidad de analizar un incidente cibernético completo. En lugar de reportar eventos aislados, correlacioné cada hallazgo técnico con las fases de la Cyber Kill Chain, documentando paso a paso cómo el atacante logró entrar, qué herramientas ejecutó y cómo aseguró su control sobre la máquina.

---

## 🟢 1. Fase 1: Acceso Inicial (Initial Access)

En esta fase, investigué cómo el atacante logró romper el perímetro de autenticación del servidor.

* 🔵 **Intrusión por Fuerza Bruta:** Al analizar los registros de auditoría en `Security.evtx` y filtrar por el **Event ID 4625** (*Logon Failure*), detecté una ráfaga masiva de intentos de autenticación fallidos contra la cuenta `Administrator`. El atacante continuó este ataque de diccionario hasta lograr adivinar la credencial, consolidando su acceso interactivo por Escritorio Remoto (comprobable mediante el **Event ID 4624**, Tipo de inicio de sesión 10).

---

## 🟢 2. Fase 2: Entrega de Carga Útil (Delivery)

Una vez que el atacante estuvo dentro del sistema a través de RDP, procedió a alojar sus herramientas maliciosas para operar dentro de la máquina.

* 🔵 **Entrega del Payload:** Utilizando la telemetría de `Sysmon.evtx` y filtrando por el **Event ID 11** (*File Created*), identifiqué la creación de artefactos sospechosos en el sistema con doble extensión y marcas de descarga directa.

> **Contexto Forense:** El análisis del *Alternate Data Stream* `Zone.Identifier` en los archivos arrojados confirmó que estos provinieron de una descarga de Internet, materializando la entrega efectiva del código malicioso en el equipo comprometido.

> 🎥 **VIDEO DEMOSTRATIVO PARTE 1 (Acceso Inicial y Carga de Payload):**  
> 🔗 [Ver demostración en video: Fuerza Bruta y Delivery](PEGA_AQUI_TU_LINK_DEL_VIDEO_1)

---

## 🟢 3. Fase 3: Persistencia y Escalada de Privilegios (Persistence & Privilege Escalation)

Sabiendo que la contraseña comprometida del administrador podía ser revocada por el equipo de TI, el atacante ejecutó acciones tácticas para asegurar una puerta trasera permanente.

* 🔵 **Creación de Cuenta Trampa:** Revisando `Security.evtx` mediante el **Event ID 4720**, detecté la creación manual de un usuario local llamado `support`.
* 🔵 **Escalada de Privilegios:** Inmediatamente después de crear la cuenta, el registro arrojó el **Event ID 4732** (*Security-enabled local group modification*). Esto demostró que el atacante agregó manualmente al usuario `support` al grupo `Administrators`, garantizándole permisos de nivel de sistema y acceso RDP sin depender de la cuenta original.

---

## 🟢 4. Fase 4: Persistencia Avanzada (Installation & Persistence)

Para asegurar que el malware se ejecutara de forma automática y silenciosa en cada reinicio del servidor sin intervención humana, el atacante utilizó dos métodos de evasión adicionales:

* 🔵 **Abuso de Servicios del Sistema:** El atacante registró un servicio malicioso apuntando a rutas inusuales. Al revisar el **Event ID 4697** (*A service was installed in the system*), evidencié que el binario fue instalado camuflándose bajo el nombre aparentemente legítimo de *Data Protection Service*, pero apuntando a la ruta anómala `C:\Windows\Help\`.
* 🔵 **Tareas Programadas Engañosas:** También se programó la ejecución de código. Analizando el contenido XML de la tarea en el **Event ID 4698**, detecté que se registró utilizando el nombre engañoso *Amazon Sync* para despistar a los administradores del sistema.

---

## 🟢 5. Fase 5: Comando y Control (Command and Control)

El objetivo final de toda esta persistencia era mantener comunicación constante con la infraestructura del atacante (Servidor C2).

* 🔵 **Validación de Ejecución en Memoria:** Al analizar Sysmon mediante el **Event ID 1** (*Process Creation*), rastreamos el comportamiento del proceso malicioso, confirmando a través del campo *ParentImage* que los servicios y tareas creadas en la Fase 4 lograron levantar exitosamente el *payload* en memoria operando en segundo plano.
* 🔵 **Conexión C2 y Canal DNS:** Para validar el canal saliente, filtramos `Sysmon.evtx` por el **Event ID 22** (*DNSEvent*). Detectamos las consultas DNS iniciadas por el proceso anómalo, logrando vincular la ejecución del *payload* directamente con la resolución del dominio de la infraestructura de Comando y Control del atacante.

> 🎥 **VIDEO DEMOSTRATIVO PARTE 2 (Persistencia, C2 y Triaje Completo):**  
> 🔗 [Ver investigación completa en video: Persistencia, C2 y Detección](PEGA_AQUI_TU_LINK_DEL_VIDEO_2)

---

## 🟢 6. Resumen de Indicadores de Compromiso (IoCs)

Tabla de referencias cruzadas con los artefactos técnicos y registros auditados a lo largo del caso:

| Fase Kill Chain | Artefacto / Indicador Técnico (IoC) | Origen y Event ID |
| :--- | :--- | :--- |
| **Initial Access** | Ráfaga de fuerza bruta y acceso RDP exitoso (Tipo 10) | `Security.evtx` 🟣 ID 4625 / 4624 |
| **Delivery** | Creación de archivos y rastros de descarga (`Zone.Identifier`) | `Sysmon.evtx` 🟣 ID 11 |
| **Persistence** | Creación cuenta `support` y asignación a `Administrators` | `Security.evtx` 🟣 ID 4720 / 4732 |
| **Persistence** | Servicio falso *Data Protection Service* en `C:\Windows\Help` | `Security.evtx` 🟣 ID 4697 |
| **Persistence** | Tarea programada maliciosa camuflada como *Amazon Sync* | `Security.evtx` 🟣 ID 4698 |
| **Execution** | Proceso hijo malicioso lanzado desde el servicio/tarea (`ParentImage`) | `Sysmon.evtx` 🟣 ID 1 |
| **C2 / Exfil** | Consultas salientes hacia el dominio/IP del atacante | `Sysmon.evtx` 🟣 ID 22 / ID 3 |

---

## 🟢 7. Cierre del Informe Forense y Mitigación

La elaboración de este informe refleja mi capacidad técnica para realizar triaje de eventos de seguridad en sistemas Windows. Al atajar la amenaza en la fase de Comando y Control, se evitaron acciones de impacto sobre el objetivo (exfiltración o cifrado).

Para contener el incidente, las acciones inmediatas radican en:
1. Aislar el host de la red.
2. Revocar las credenciales del Administrador y eliminar la cuenta `support`.
3. Purgar el servicio *Data Protection Service* y la tarea *Amazon Sync*.

A nivel preventivo, se requiere restringir la exposición del puerto 3389 (RDP) detrás de una VPN con MFA e implementar políticas de bloqueo de cuenta ante ráfagas de autenticación fallida.
