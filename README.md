# Demiurge

App de escritorio para Windows que te muestra qué hace tu PC y te explica, en lenguaje simple, si hay señales de infección. Es una herramienta de **visibilidad y segunda opinión**: **no es un antivirus** y no reemplaza a Defender.

Está basada en `windows-security-dashboard-spec.xlsx` y en las decisiones de diseño que se tomaron después:
- Las señales se agrupan por entidad (no hay motor estilo SIEM).
- Se usan APIs nativas de Windows primero.
- La privacidad va primero y el veredicto es honesto.
- **No queda nada corriendo en segundo plano.**

> Estado: **beta**. Puede tener errores (ver "Qué falta verificar").

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
archive/              Servicio, modo vivo (ETW), named pipe y MCP: fuera de la compilación, conservados por si se recuperan
```

Stack: .NET 10 (LTS), WPF + WebView2, React 19 + Vite, System.Management (WMI), TaskScheduler (dahall), Microsoft.Data.Sqlite, YamlDotNet, WiX 6 y P/Invoke (WinVerifyTrust, iphlpapi, tokens, dnsapi).

## Compilar y probar

```powershell
dotnet build Demiurge.sln          # también compila la interfaz con npm si hace falta (requiere Node.js)
dotnet test Demiurge.sln

# Instalador: corre los tests, publica la app autocontenida y arma artifacts\DemiurgeSetup.msi
.\build-installer.ps1 [-Version 0.1.0]

# Interfaz con datos de ejemplo en el navegador (sin motor):
cd src\Demiurge.App\web; npm run dev

# Consola (como administrador):
src\Demiurge.Cli\bin\Debug\net10.0-windows\demiurge.exe scan | status | findings | inventory startup | diff
```

Los datos se guardan en `%ProgramData%\Demiurge`. La variable de entorno `DEMIURGE_HOME` cambia esa ubicación, para hacer pruebas.

## El instalador

`DemiurgeSetup.msi` (unos 53 MB, porque incluye .NET y no hay que instalar nada aparte):
- Instala en `C:\Program Files\Demiurge`, donde sólo los administradores pueden escribir.
- Crea accesos directos en el menú Inicio y el Escritorio.
- Muestra un aviso de beta: no es un antivirus y no hay garantía.
- No instala servicios ni tareas programadas.
- Requiere Windows 10/11 de 64 bits y WebView2 Runtime (viene con Windows 11). Si falta, el instalador avisa.
- Desinstalar no borra `C:\ProgramData\Demiurge` (historial de escaneos).
- **No está firmado**: SmartScreen va a advertir hasta que se firme con un certificado de firma de código.

## Motores de detección

Demiurge junta lo que encuentran varias herramientas y lo explica en una sola tarjeta por programa:

| Motor | Qué aporta | Cuándo corre |
|---|---|---|
| Reglas propias (H-01…H-31) | "Esto es raro": sin firma, carpeta rara, imita a Windows, arranca solo, LOLBins… | Siempre |
| Listas de amenazas (abuse.ch, etc.) | "Habla con un servidor denunciado", "es un hash conocido" | Siempre |
| **YARA-X + YARA Forge** (incluido) | "Tiene rasgos de la familia X": miles de reglas curadas, que se actualizan solas cada semana | Programas en ejecución, arranque, descargas y sospechosos (escaneo profundo: todo lo que no firma Microsoft) |
| **HollowsHunter** (incluido) | "Algo se inyectó en la memoria de este programa" | Procesos sospechosos (escaneo profundo: todos) |
| **Hayabusa** (incluido, edición live-response) | Miles de reglas Sigma sobre todos los registros de eventos de Windows (H-31) | Cada escaneo: últimos 7 días (profundo: 30). Necesita administrador |
| Historial de ejecución (BAM, UserAssist, PCA, Prefetch) | Qué se ejecutó aunque ya no exista: "se ejecutó desde AppData y desapareció" (H-34), "factura.pdf.exe se ejecutó" (H-21) | Siempre (BAM y Prefetch necesitan administrador) |
| Inicios de sesión | Escritorio remoto, con pregunta "¿fuiste vos?" (H-35), y contraseñas probadas por fuerza bruta (H-36) | Siempre (necesita administrador) |
| Reglas del firewall | Programa sin firma en una carpeta de usuario con una regla para recibir conexiones (H-37) | Siempre |
| **Microsoft Defender** (el de Windows) | "Defender confirma que es Trojan:Win32/…" (H-32), y su historial: "lo detectó el martes y el archivo sigue ahí" (H-33) | Sobre lo que quedó sospechoso y lo que marcó YARA, con `-DisableRemediation`: no borra nada por su cuenta |

**Cuando los motores no coinciden, se baja la alarma.** Si YARA marca algo pero Defender lo analizó y no encontró nada, la señal pesa mucho menos y la tarjeta lo dice: "puede ser un falso positivo". Si además el archivo tiene firma válida, queda como informativo. Las reglas de baja confianza (score de YARA Forge menor a 70, o reglas `CAPE_*` pensadas para memoria) también pesan menos.

Las reglas YARA se compilan **en memoria** en cada escaneo. Un archivo de reglas compiladas en disco lo bloquea el antivirus, porque contiene miles de patrones de malware, y excluirlo del antivirus sería justo lo que hace el malware.

Las herramientas incluidas tienen la versión y el hash fijados en `src/Demiurge.Core/Resources/tools.lock.json`. `build-installer.ps1` verifica el zip y el ejecutable antes de incluirlos, y la app vuelve a verificar el hash antes de cada ejecución.

## Trazabilidad con la planilla

| Pestaña / ID | Implementación |
|---|---|
| 01 Arquitectura | App WPF + WebView2 con el motor en el mismo proceso (decisión posterior a la planilla: sin servicio). `Core/Ipc/Protocol` es el contrato entre la interfaz y el motor |
| COL-01 | `ProcessCollector` (WMI + tokens: integridad, elevación, usuario) |
| COL-02/03/04 | **Sacados**: requerían telemetría ETW permanente (código en `archive/`) |
| COL-05/16 | `DnsCollector`: log DNS-Client si está habilitado + caché DNS |
| COL-06 / COL-07 | `Native/WinTrust` (embebida + catálogo + paquetes MSIX), `Enrichment/FileHasher` |
| COL-08…13 | `RegistryPersistence`, `StartupFolder`, `ScheduledTask` (incluye tareas escondidas sin SD), `Service`, `WmiPersistence`, `OtherPersistence` (BITS, LSA, COM hijack, Office) |
| COL-14/15 | `NetworkConnection`, `NetworkConfig` (hosts, DNS estático/DHCP, proxy WinINET/WinHTTP) |
| COL-17…22 | `Defender`, `SecurityPosture`, `Account`, `Certificate`, `InstalledSoftware`, `Browser` (Chromium x6 + Firefox, todos los perfiles) |
| COL-23…26 | `EventLog`, `Driver`, `RecentFiles` (Mark-of-the-Web), `Resource` (CPU/GPU en ventana) |
| EXT-01…03 | `External/ExternalTools` (YARA-X, HollowsHunter, Hayabusa), `ExternalRunner` (dueño administrador + SHA256 fijado). Sysmon (EXT-04) no se instala desde la app porque queda corriendo en segundo plano |
| TI-01…13 | `Intel/FeedStore` + `FeedUpdater` (se actualizan al abrir la app), `Enrichment/ReputationService` (sólo por hash), `Resources/knowledgebase.json` |
| H-01…H-31 | `Resources/heuristics.yaml` + `Rules/Heuristics.cs`. H-23 y H-24 están desactivadas (necesitaban ETW). **H-25 (beaconing)** se reimplementó comparando escaneos cercanos: un programa sin firma que sigue conectado al mismo destino en dos escaneos separados por 15 min a 48 h |
| 06 Scoring | `Scoring/ScoringEngine` |
| 07 Modelo de datos | `Model/*`, `Storage/DemiurgeDb` |
| 08 UX | Interfaz en `src/Demiurge.App/web`: veredicto, tarjetas de 4 preguntas, inventario, novedades (diff), actividad con deshacer, ajustes |

## Seguridad de Demiurge mismo

La app corre como administrador mientras está abierta, así que la diseñamos para que no la usen como trampolín:

| Riesgo | Defensa |
|---|---|
| Un programa sin privilegios planta ejecutables, reglas o feeds en `%ProgramData%\Demiurge` (por defecto escribible por usuarios) | `Security/DataDirectoryLockdown`: sólo SYSTEM y Administradores tienen acceso. Lo que creó otro usuario se aparta sin cargarse, y la recorrida nunca entra en enlaces |
| Junctions, symlinks o hardlinks para que la app escriba o borre otro archivo | `Native/SafeFile`: verifica la ruta real del handle, rechaza hardlinks y opera y borra sobre el mismo handle. La cuarentena exige el mismo hash del escaneo |
| La WebView2 corre elevada | Sólo carga la interfaz local (`app.demiurge.example`), con CSP sin red. Cancela cualquier otra navegación, ventanas nuevas y descargas. Sin devtools ni menús en Release. Sólo acepta mensajes de la interfaz y operaciones del protocolo |
| Abrir links desde un proceso elevado los abriría elevados | La app no abre links externos |
| Herramientas externas reemplazadas | Dueño administrador y SHA256 fijado antes de cada ejecución |
| Algo queda escuchando | No hay servicio ni pipe: al cerrar la ventana, no queda nada |

Tests: `tests/Demiurge.Tests/SecurityTests.cs` intenta los ataques de verdad (junction, hardlink, archivo cambiado, pedidos sin elevación).

## Calibración (PC limpia real, 14/10/2026)

| Falso positivo | Corrección |
|---|---|
| Extensiones internas de Firefox (`app-builtin-addons`) | Se excluyen `app-builtin*` y `app-system*` |
| Sin admin, Defender devuelve "N/A: Must be an administrator…" como exclusión | Se filtran esos valores |
| 40 juegos de Steam sin firma salían "Revisar" por reglas del firewall | El historial y el firewall no cuentan como "activos"; H-37 exige sin firma + carpeta de usuario y pesa 15 |
| `Spotify.dll` salía Peligroso por la regla YARA `CAPE_Bumblebee` (Defender lo dio por limpio) | Contraste YARA ↔ Defender ↔ firma; reglas `CAPE_*` como baja confianza |
| `files.pythonhosted.org` y `cdn.jsdelivr.net` salían Peligroso (URLhaus lista URLs en hostings compartidos) | En hostings y CDNs compartidos se matchea sólo la URL exacta (`SharedHosts`) |
| Apps firmadas instaladas por usuario (Notion, Battle.net) disparaban H-08 | `signed_user_folder_counts: false` |
| Binarios de apps MSIX (sin firma propia) | Se toma la firma del paquete |
| Certificados locales de EA y Battle.net (H-16) | KB con `requiresSoftware`: sólo son benignos si el programa está instalado |

Pesos y umbrales siguen siendo la propuesta inicial de la planilla. Falta medir la detección en VMs con muestras reales.

## Qué falta verificar

- **La app instalada desde el MSI** y corriendo como administrador. Se probó la app sin elevar, sobre los datos de un escaneo ya hecho.
- **Escanear desde la interfaz**: el botón "Escanear ahora" con su barra de progreso y el refresco al terminar.
- Escaneo como **administrador**: log de Security, exclusiones de Defender, todos los perfiles.
- **Acciones** sobre el sistema real. Sólo se probó allowlist/revert.
- **Herramientas externas** y **consultas online por hash** (desactivadas durante las pruebas).
- **Detección real** en VMs con malware (stealer, miner, RAT, adware).
- Antes de compartirlo: revisión de seguridad por una persona, firma de código y publicar el código para que se pueda auditar.

## Ajustar reglas sin recompilar

Copiá `src/Demiurge.Core/Resources/heuristics.yaml` (o `knowledgebase.json`) a `%ProgramData%\Demiurge\rules\` como administrador y editalo. Se recarga en cada escaneo.
