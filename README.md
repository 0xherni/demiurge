# Demiurge

> [!WARNING]
> **Recomiendo no descargarlo ni instalarlo.** Demiurge pasó una auditoría de seguridad (ver [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md)) y se corrigieron todos los problemas encontrados, pero eso no lo vuelve seguro: es una app que corre **con permisos de administrador** y lee, analiza y modifica partes sensibles de Windows (arranque, registro, navegadores, certificados, cuentas, antivirus). Cualquier bug que quede en un programa con ese nivel de acceso puede ser aprovechado o romper el sistema. Además, el proyecto está **discontinuado**, no tiene firma digital y su detección no se midió con malware real. Está publicado como proyecto de portfolio, para leer el código.

## Qué es

Demiurge es una app de escritorio para Windows 10/11 que revisa la PC y responde una pregunta simple: **¿mi PC está limpia o infectada?** Junta las señales que deja Windows, las analiza con varios motores de detección y explica cada hallazgo en español simple, sin jerga.

Es una herramienta de **visibilidad y segunda opinión**. **No es un antivirus**: no protege en tiempo real, no bloquea nada y no reemplaza a Microsoft Defender.

## Para qué sirve

- **"Creo que estoy infectado"**: la PC anda rara, aparecen publicidades o cambió el buscador.
- **"Me llamaron por teléfono y me hicieron instalar algo"**: detecta programas de control remoto y pregunta si los instalaste vos.
- **"Pegué un comando que me pidió una página"** (estafa *ClickFix*): encuentra el comando y explica qué hizo.
- **"Instalé un crack o algo dudoso"**: muestra si quedó algo arrancando solo, conectándose o escondido, aunque el programa ya se haya borrado.
- **"Me robaron una cuenta"**: busca rastros de ladrones de contraseñas (incluso los que se borran solos) y aplicaciones modificadas, como Discord.
- **Revisiones periódicas**: compara cada escaneo con el anterior y muestra qué apareció de nuevo.

## A quién está apuntado

A **usuarios hogareños sin conocimientos técnicos**. Cada hallazgo responde cuatro preguntas (qué encontramos, por qué, qué tan grave es, qué hago), las palabras técnicas tienen un glosario al pasar el mouse, y hay un plan de limpieza paso a paso. Para quien sabe más, cada tarjeta tiene un detalle técnico con los datos crudos, las reglas que se activaron y su técnica de MITRE ATT&CK.

## Qué hace la aplicación

**Revisa** (28 áreas de Windows, con APIs nativas):
- Procesos, conexiones de red, caché DNS y consumo sostenido de CPU/GPU.
- Todo lo que arranca solo: registro, servicios, tareas programadas, carpeta Inicio, WMI, BITS, paquetes LSA, COM hijacking, complementos de Office.
- Navegadores (Chrome, Edge, Brave, Opera, Vivaldi, Firefox): extensiones, buscador, página de inicio, notificaciones y políticas.
- Red: archivo hosts, DNS, proxy y reglas del firewall.
- Certificados raíz, cuentas locales, controladores y programas instalados.
- Microsoft Defender: estado, exclusiones y detecciones pasadas.
- Historial de ejecución (BAM, UserAssist, PCA, Prefetch, Amcache, ShimCache), incluido lo que ya se borró.
- Comandos escritos en Win+R, en la barra del Explorador y en PowerShell.
- Integridad de aplicaciones (Discord modificado por ladrones de cuentas).
- Registros de eventos: servicios nuevos, registros borrados, cuentas creadas, inicios de sesión remotos, contraseñas probadas por fuerza bruta.
- Salud del sistema: firewall, UAC, SmartScreen, Escritorio remoto, Windows Update, Secure Boot, BitLocker.

**Analiza**: 40 reglas propias agrupan las señales por programa (no por evento) y les dan un puntaje. Una señal sola pesa poco; varias juntas pesan mucho. Cuando dos motores no coinciden, se baja la alarma y la tarjeta lo dice.

**Explica y guía**:
- **Veredicto**: limpio, revisar o probable infección.
- **Tarjetas**: una por programa, con las 4 preguntas y preguntas al usuario cuando sólo él sabe la respuesta ("¿instalaste vos AnyDesk?").
- **Plan de limpieza**: los hallazgos convertidos en pasos ordenados, desde cortar el daño hasta volver a escanear, con la lista de cuentas para cambiar contraseña.
- **Qué pasó**: línea de tiempo con fechas reales; sólo une eventos cuando es el mismo archivo y no inventa causas.
- **Inventario**: todo lo que hay en la PC, cada cosa con "¿qué es?" y "¿es normal?".
- **Novedades**: qué cambió desde el escaneo anterior.

**Actúa (siempre con confirmación y reversible)**: deshabilitar un arranque, poner en cuarentena (sin borrar), quitar extensiones, restaurar el navegador, el proxy o el archivo hosts, quitar exclusiones del antivirus o certificados, reparar Discord. Todo se puede deshacer desde "Actividad", salvo finalizar un proceso.

**No deja nada corriendo**: trabaja sólo mientras la ventana está abierta. No instala servicios ni tareas programadas.

## Herramientas conectadas

| Herramienta | Para qué | Cómo se usa |
|---|---|---|
| **Microsoft Defender** (incluido en Windows) | Segunda opinión sobre lo sospechoso y su historial de detecciones | `MpCmdRun` con `-DisableRemediation`: analiza pero no borra nada por su cuenta |
| **YARA-X** + reglas **YARA Forge** | Rasgos de familias de malware conocidas dentro de los archivos | Incluido en el instalador; las reglas se actualizan cada semana |
| **HollowsHunter** (PE-sieve) | Código inyectado en la memoria de programas legítimos | Incluido en el instalador |
| **Hayabusa** + reglas **Sigma** | Miles de reglas de la comunidad sobre los registros de eventos de Windows | Incluido en el instalador (edición live-response) |
| **abuse.ch** (ThreatFox, URLhaus, Feodo Tracker) | Servidores, dominios y hashes maliciosos conocidos | Listas descargadas y comparadas en la PC |
| **LOLBAS** y **LOLDrivers** | Herramientas de Windows usadas para atacar y drivers vulnerables | Listas descargadas |
| **Lista de raíces de Microsoft** (authroot) | Detectar certificados raíz agregados en la PC | Descargada y verificada por firma |
| **CIRCL hashlookup** | Saber si un archivo es software conocido | Consulta sólo por hash; nunca se sube un archivo |
| **MalwareBazaar** | Saber si un hash es malware conocido | Consulta sólo por hash |
| **VirusTotal** (opcional) | Opinión de más de 70 antivirus | Con la clave gratuita del usuario; sólo por hash |

Las herramientas incluidas tienen versión y hash fijados en `src/Demiurge.Core/Resources/tools.lock.json`, y la app verifica el hash antes de cada ejecución.

## Estado del proyecto

**Discontinuado** (octubre 2026), en beta.
- Probado en una PC real sin permisos de administrador, con calibración de falsos positivos (ver más abajo).
- 102 tests automáticos, incluidos los que intentan los ataques corregidos en la auditoría.
- **No verificado**: el funcionamiento completo instalado desde el MSI y corriendo como administrador, las acciones sobre un sistema real, y la detección con malware real en máquinas virtuales.
- El instalador **no está firmado**: Windows SmartScreen lo advierte.

---

## Arquitectura

```
Demiurge.exe (WPF, pide administrador al abrirse)
 ├─ WebView2 → interfaz React + TypeScript (src/Demiurge.App/web), servida desde una carpeta local
 └─ Motor (Demiurge.Core) en el mismo proceso: colectores → reputación → reglas → scoring → SQLite
Al cerrar la ventana termina todo: no hay servicio, ni pipe, ni tareas programadas.
```

```
src/
  Demiurge.Core/      Motor: colectores, enriquecimiento, inteligencia, reglas, scoring, storage, acciones
  Demiurge.App/       App de escritorio (WPF + WebView2) y su interfaz en web/
  Demiurge.Cli/       Consola para desarrollo y diagnóstico (mismo motor)
tests/Demiurge.Tests/ Tests de reglas, scoring, parsers y seguridad
installer/            Instalador MSI (WiX 6)
archive/              Servicio, modo vivo (ETW), named pipe y MCP: fuera de la compilación
```

Stack: .NET 10 (LTS), WPF + WebView2, React 19 + Vite + TypeScript, System.Management (WMI), TaskScheduler, Microsoft.Data.Sqlite, YamlDotNet, WiX 6 y P/Invoke (WinVerifyTrust, iphlpapi, tokens, dnsapi, ntdll).

Basado en una planilla de especificación propia (`windows-security-dashboard-spec.xlsx`: colectores, herramientas externas, inteligencia, heurísticas, scoring, modelo de datos y UX) y en decisiones de diseño posteriores:
- Las señales se agrupan por entidad (no hay motor estilo SIEM).
- APIs nativas de Windows primero.
- Privacidad primero: nada se sube, sólo se consultan hashes.
- Veredicto honesto.
- Nada corriendo en segundo plano.

## Compilar y probar

```powershell
dotnet build Demiurge.sln          # también compila la interfaz con npm si hace falta (requiere Node.js)
dotnet test Demiurge.sln

# Instalador: corre los tests, publica la app autocontenida y arma artifacts\DemiurgeSetup.msi
.\build-installer.ps1 [-Version 0.1.0]

# Interfaz con datos de ejemplo en el navegador (sin motor):
cd src\Demiurge.App\web; npm run dev

# Consola (como administrador):
src\Demiurge.Cli\bin\Debug\net10.0-windows\demiurge.exe scan | status | findings | plan | timeline | inventory startup | diff
```

Los datos se guardan en `%ProgramData%\Demiurge`. Sin permisos de administrador (desarrollo y pruebas), la variable `DEMIURGE_HOME` cambia esa ubicación; corriendo como administrador se ignora.

## El instalador

`DemiurgeSetup.msi` (unos 66 MB: incluye .NET y las herramientas, no hay que instalar nada aparte):
- Instala en `C:\Program Files\Demiurge`, donde sólo los administradores pueden escribir.
- Crea accesos directos en el menú Inicio y el Escritorio.
- Muestra un aviso de beta: no es un antivirus y no hay garantía.
- No instala servicios ni tareas programadas.
- Requiere Windows 10/11 de 64 bits y WebView2 Runtime (viene con Windows 11). Si falta, el instalador avisa.
- Desinstalar no borra `C:\ProgramData\Demiurge` (historial de escaneos).
- **No está firmado.**

## Motores de detección

| Motor | Qué aporta | Cuándo corre |
|---|---|---|
| Reglas propias (H-01…H-40) | "Esto es raro": sin firma, carpeta rara, imita a Windows, arranca solo, LOLBins… | Siempre |
| Listas de amenazas (abuse.ch, etc.) | "Habla con un servidor denunciado", "es un hash conocido" | Siempre |
| **YARA-X + YARA Forge** | "Tiene rasgos de la familia X" | Programas en ejecución, arranque, descargas y sospechosos (escaneo profundo: todo lo que no firma Microsoft) |
| **HollowsHunter** | "Algo se inyectó en la memoria de este programa" | Procesos sospechosos (escaneo profundo: todos) |
| **Hayabusa** | Reglas Sigma sobre todos los registros de eventos (H-31) | Cada escaneo: últimos 7 días (profundo: 30). Necesita administrador |
| Historial de ejecución | Qué se ejecutó aunque ya no exista (H-34, H-21); con el SHA1 de Amcache, si lo borrado era malware conocido (H-40) | Siempre (BAM, Prefetch y Amcache necesitan administrador) |
| Comandos escritos | Estafa "ClickFix" (H-38), con la pregunta "¿te lo pidió una página?" | Siempre |
| Integridad de aplicaciones | Discord modificado por un ladrón de cuentas (H-39), con "Reparar Discord" | Siempre |
| Inicios de sesión | Escritorio remoto (H-35) y fuerza bruta (H-36) | Siempre (necesita administrador) |
| Reglas del firewall | Programa sin firma en carpeta de usuario que recibe conexiones (H-37) | Siempre |
| **Microsoft Defender** | Confirmación (H-32) e historial (H-33) | Sobre lo sospechoso y lo que marcó YARA |

**Cuando los motores no coinciden, se baja la alarma.** Si YARA marca algo pero Defender no encontró nada, la señal pesa mucho menos y la tarjeta dice "puede ser un falso positivo". Las reglas YARA se compilan **en memoria** en cada escaneo: un archivo de reglas compiladas en disco lo bloquea el antivirus, y excluirlo sería justo lo que hace el malware.

## Seguridad de Demiurge mismo

La app corre como administrador mientras está abierta, así que está diseñada para que no la usen como trampolín. El detalle de la auditoría (herramientas usadas, 21 hallazgos y sus correcciones) está en [`SECURITY-AUDIT.md`](SECURITY-AUDIT.md).

| Riesgo | Defensa |
|---|---|
| Un programa sin privilegios planta archivos o enlaces en `%ProgramData%\Demiurge` | `Security/DataDirectoryLockdown`: sólo SYSTEM y Administradores tienen acceso; una carpeta plantada o enlazada se aparta sin tocar su destino; lo que creó otro usuario no se carga |
| Junctions, symlinks o hardlinks para que la app escriba o borre otro archivo | `Native/SafeFile`: verifica la ruta real del handle, rechaza hardlinks, y crea o restaura relativo a la carpeta ya verificada |
| Firmas falsas "de Microsoft" | Se exige que la cadena de certificados termine en una raíz real de Microsoft; las firmas con raíces agregadas en la PC no cuentan |
| La WebView2 corre elevada | Sólo carga la interfaz local con CSP sin red; perfil nuevo en cada apertura; sin navegación externa, ventanas nuevas, descargas ni devtools |
| Abrir links desde un proceso elevado | La app no abre links externos |
| Herramientas externas reemplazadas | Dueño administrador y SHA256 fijado antes de cada ejecución |
| Acciones peligrosas por un falso positivo | Nunca finaliza procesos críticos ni mueve archivos de Windows o de Microsoft; todo pide confirmación y se puede deshacer |

Tests: `tests/Demiurge.Tests/SecurityTests.cs` y `SecurityAuditTests.cs` intentan los ataques de verdad.

## Calibración (PC limpia real, 14/10/2026)

| Falso positivo | Corrección |
|---|---|
| Extensiones internas de Firefox (`app-builtin-addons`) | Se excluyen `app-builtin*` y `app-system*` |
| Sin admin, Defender devuelve "N/A: Must be an administrator…" como exclusión | Se filtran esos valores |
| 40 juegos de Steam sin firma salían "Revisar" por reglas del firewall | El historial y el firewall no cuentan como "activos"; H-37 exige sin firma + carpeta de usuario y pesa 15 |
| `Spotify.dll` salía Peligroso por la regla YARA `CAPE_Bumblebee` (Defender lo dio por limpio) | Contraste YARA ↔ Defender ↔ firma; reglas `CAPE_*` como baja confianza |
| `files.pythonhosted.org` y `cdn.jsdelivr.net` salían Peligroso (URLhaus lista URLs en hostings compartidos) | En hostings compartidos se matchea sólo la URL exacta |
| Apps firmadas instaladas por usuario (Notion, Battle.net) disparaban H-08 | `signed_user_folder_counts: false` |
| Binarios de apps MSIX (sin firma propia) | Se toma la firma del paquete |
| Instaladores oficiales con `irm … \| iex` en el historial de PowerShell (H-38) | Lista `trusted_hosts` (dominio exacto, nunca hostings compartidos) |
| Certificados locales de EA y Battle.net (H-16) | Sólo son benignos si el programa está instalado |

Pesos y umbrales siguen siendo la propuesta inicial de la planilla.

## Ajustar reglas sin recompilar

Copiá `src/Demiurge.Core/Resources/heuristics.yaml` (o `knowledgebase.json`) a `%ProgramData%\Demiurge\rules\` como administrador y editalo. Se recarga en cada escaneo.
