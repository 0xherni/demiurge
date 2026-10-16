# Auditoría de seguridad — 15/10/2026

Demiurge corre como administrador y lee datos que controla cualquier programa del usuario. La auditoría buscó, sobre todo, formas de que un programa sin privilegios use a Demiurge para hacer algo como administrador, romper Windows o esconderse.

## Capa 1: herramientas automáticas

| Herramienta | Resultado |
|---|---|
| `dotnet list package --vulnerable --include-transitive` | Sin vulnerabilidades conocidas |
| `npm audit` (interfaz) | 0 vulnerabilidades |
| Gitleaks (historial de git + carpeta) | Sin secretos reales (un hash de ejemplo de los datos de demostración) |
| Semgrep (C#, TypeScript/React, OWASP Top 10, CWE Top 25, secretos) | 1 alerta de inyección SQL: falso positivo (todas las consultas usan parámetros) |
| Analizadores de .NET con todas las reglas | 30 llamadas nativas sin ruta de carga fija (CA5392): corregido. El resto, revisado: falsos positivos o recursos de vida igual al proceso |

## Capa 2: revisión manual

| # | Gravedad | Hallazgo | Corrección |
|---|---|---|---|
| 1 | Crítica | La variable de entorno `DEMIURGE_HOME` (la puede definir cualquier programa del usuario) cambiaba la carpeta de datos de la app elevada | Se ignora cuando la app corre como administrador |
| 2 | Crítica | Si `C:\ProgramData\Demiurge` existía como enlace a otra carpeta, la protección de permisos se aplicaba al destino del enlace | Una carpeta raíz que es enlace, archivo o de otro dueño se aparta renombrándola (sin tocar el destino) y se crea una nueva con los permisos puestos desde el inicio |
| 3 | Alta | El log se escribía antes de proteger la carpeta de datos | El log espera en memoria hasta que la carpeta está protegida |
| 4 | Alta | El perfil del navegador interno (WebView2) estaba en `%LOCALAPPDATA%`, escribible por cualquier programa del usuario | Movido a la carpeta de datos protegida |
| 5 | Alta | "Firmado por Microsoft" se decidía sólo por el nombre del firmante | Se exige que la cadena de certificados termine en una raíz real de Microsoft, verificada criptográficamente |
| 6 | Alta | Las apps MSIX se daban por firmadas por Microsoft según el nombre de la carpeta | Sólo dentro de `%ProgramFiles%\WindowsApps` y `%windir%\SystemApps`, y el firmante sale del certificado del paquete |
| 7 | Alta | Firmas que terminan en una raíz agregada en la PC contaban como válidas | Si la raíz no es pública ni de Microsoft, la firma no cuenta como válida |
| 8 | Alta | Hashes que CIRCL lista como maliciosos se marcaban como "conocidos buenos" | Nunca entran en la lista blanca; la caché vieja se invalida |
| 9 | Alta | "Eliminar tarea oculta" (WMI) armaba la consulta con el nombre de la tarea | Se recorren las instancias y se compara el nombre exacto; se borra sólo esa |
| 10 | Alta | "Finalizar programa" podía cerrar procesos críticos de Windows | Procesos críticos, de Windows firmados por Microsoft y la propia app protegidos; se verifica que el PID no se haya reutilizado |
| 11 | Media | La cuarentena sólo protegía System32 | Nada de la carpeta de Windows, nada firmado por Microsoft y nada de Demiurge |
| 12 | Media | Restaurar un archivo o carpeta verificaba la carpeta y después escribía por ruta | Se crea / mueve relativo al handle de la carpeta ya verificada |
| 13 | Media | `netsh` e `ipconfig` se ejecutaban por nombre | Ruta completa de System32 |
| 14 | Media | Los permisos de Firefox se copiaban a la `%TEMP%` del usuario sin verificar la ruta | Copia verificada a la carpeta protegida |
| 15 | Media | El mutex de instancia única lo podía crear cualquier programa para que Demiurge no abra | Sólo se respeta si de verdad hay otra ventana de Demiurge abierta |
| 16 | Media | Deshacer "inicio de sesión" restauraba `C:\Windows\...` fijo | Usa la carpeta real de Windows |
| 17 | Media | Llamadas nativas sin ruta de carga fija | DLLs de Windows sólo desde System32 |
| 18 | Baja | Expresiones regulares sobre contenido del usuario podían colgar el escaneo | Motor sin retroceso (`NonBacktracking`) |
| 19 | Baja | Descargas y extracción de reglas sin límite de tamaño | Topes de tamaño |
| 20 | Baja | Código que descargaba e instalaba Sysmon (sin uso) | Eliminado |
| 21 | Baja | Los datos de demostración se empaquetaban en la app | Sólo existen en modo desarrollo |

Tests: `tests/Demiurge.Tests/SecurityAuditTests.cs` intenta cada abuso corregido (14 tests).

## Lo que esta auditoría no cubre

- Pruebas dinámicas con la app instalada (Process Monitor, tráfico de red): ver la capa 3 en la VM.
- Seguridad de los motores externos incluidos (YARA-X, HollowsHunter, Hayabusa): se verifican por hash y se ejecutan como procesos separados.
- Un malware que ya es administrador puede engañar a cualquier herramienta, Demiurge incluido.
