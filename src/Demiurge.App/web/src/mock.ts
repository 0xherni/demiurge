// Datos de EJEMPLO para desarrollar la interfaz en un navegador (fuera de la app no hay motor).
// Dentro de la app nunca se usan. Escenario: un "crack" que era un payload de Meterpreter (Metasploit)
// y después dejó Mimikatz. Las IP son de rango de documentación (203.0.113.0/24).

import type { ActionRecord, CleanupPlan, Config, DiffReport, EntityDetail, EntityScore, InventoryRow, Summary, Timeline } from "./types";

const METERPRETER = "C:\\Users\\Lucía\\AppData\\Roaming\\Microsoft\\Windows\\winupdate.exe";
const MIMIKATZ = "C:\\Users\\Public\\Libraries\\mimikatz.exe";

const findings: EntityScore[] = [
  {
    scoringKey: "4b1e9c07d2a6", kind: "Binary", displayName: "winupdate.exe", path: METERPRETER,
    score: 245, level: "Peligroso", maxSeverity: "Critica", criticalOverride: true, attackIds: ["T1059", "T1071", "T1571", "T1547.001", "T1036.005"],
    whatWeFound: "Un programa (\"winupdate.exe\") le da a otra persona control remoto de tu computadora. Es Meterpreter, una herramienta de ataque de Metasploit, y está conectado a un servidor externo.",
    whyItCaughtOurAttention: [
      "Microsoft Defender analizó \"winupdate.exe\" a pedido nuestro y confirma que es malware: Trojan:Win64/Meterpreter.B.",
      "\"winupdate.exe\" coincide con una firma de malware conocida: Meterpreter (regla SIGNATURE_BASE_Meterpreter_Reverse_TCP).",
      "\"winupdate.exe\" se está comunicando con 203.0.113.47:4444, una dirección que otros ya denunciaron por servidor de control de malware (Metasploit).",
      "\"winupdate.exe\" se configuró para arrancar solo cada vez que encendés la PC.",
      "\"winupdate.exe\" se ejecuta desde AppData, un lugar donde los programas legítimos rara vez se instalan.",
      "\"winupdate.exe\" no tiene firma digital: ningún fabricante se hace responsable de él. Por sí solo no es grave.",
    ],
    howSerious: "Crítica (Peligroso). Meterpreter le permite al atacante ver tu pantalla, leer tus archivos, registrar lo que escribís y ejecutar lo que quiera en tu PC.",
    whatToDo: "Desconectá la PC de internet ahora. Movelo a cuarentena desde acá y deshabilitá su arranque. Después cambiá tus contraseñas desde otro dispositivo.",
    availableActions: ["quarantine", "disable_startup", "kill_process", "allowlist"],
  },
  {
    scoringKey: "e83d5f1a90bc", kind: "Binary", displayName: "mimikatz.exe", path: MIMIKATZ,
    score: 200, level: "Peligroso", maxSeverity: "Critica", criticalOverride: true, attackIds: ["T1003.001", "T1558"],
    whatWeFound: "Encontramos Mimikatz, una herramienta que saca las contraseñas que Windows guarda en memoria. Los registros muestran que ya se usó en esta PC.",
    whyItCaughtOurAttention: [
      "Microsoft Defender analizó \"mimikatz.exe\" a pedido nuestro y confirma que es malware: HackTool:Win64/Mimikatz.",
      "\"mimikatz.exe\" coincide con una firma de malware conocida: Mimikatz (regla SIGNATURE_BASE_Mimikatz_Strings).",
      "Los registros de Windows muestran actividad que coincide con la regla \"HackTool - Mimikatz Execution\" (3 veces, última: lunes 12/10 23:41).",
      "\"mimikatz.exe\" no tiene firma digital: ningún fabricante se hace responsable de él. Por sí solo no es grave.",
    ],
    howSerious: "Crítica (Peligroso). Si se ejecutó, hay que asumir que el atacante tiene las contraseñas de las cuentas que usaron esta PC.",
    whatToDo: "Movelo a cuarentena. Cambiá desde otro dispositivo la contraseña de tu cuenta de Windows y de todo lo que hayas usado en esta PC.",
    availableActions: ["quarantine", "allowlist"],
  },
  {
    scoringKey: "chrome|lucía|default|hkpm", kind: "Extension", displayName: "PDF Converter Pro", score: 30, level: "Revisar", maxSeverity: "Media",
    criticalOverride: false, attackIds: ["T1176"],
    whatWeFound: "La extensión \"PDF Converter Pro\" (Chrome) puede ver todo lo que hacés en el navegador y no se instaló desde la tienda oficial.",
    whyItCaughtOurAttention: ["La extensión \"PDF Converter Pro\" (Chrome) puede ver todo lo que hacés en el navegador y no se instaló desde la tienda oficial."],
    howSerious: "Media (Revisar). Es la forma más común de adware: publicidad, redirecciones y robo de datos de navegación.",
    whatToDo: "Quitá la extensión si no la reconocés.", availableActions: ["remove_extension", "allowlist"],
  },
  {
    scoringKey: "anydesk|anydesk software gmbh", kind: "InstalledSoftware", displayName: "AnyDesk", score: 0, level: "Info", maxSeverity: "Pregunta",
    criticalOverride: false, attackIds: ["T1219"],
    whatWeFound: "AnyDesk es un programa legítimo para controlar la PC a distancia. Si lo instalaste vos o tu soporte técnico, está bien. Si alguien te llamó pidiendo que lo instales, puede ser una estafa.",
    whyItCaughtOurAttention: ["AnyDesk es un programa legítimo para controlar la PC a distancia."],
    howSerious: "Necesitamos tu respuesta. Es legítimo, pero es la herramienta preferida de las estafas telefónicas de 'soporte técnico'.",
    whatToDo: "Respondé la pregunta de abajo para que podamos evaluarlo.", availableActions: ["allowlist"],
    pendingQuestion: { questionId: "remote_tool_installed_by", text: "¿Instalaste vos AnyDesk?", options: [
      { value: "yes", label: "Sí, yo (o mi soporte técnico)", weight: 0 },
      { value: "phone", label: "Me lo pidió alguien por teléfono", weight: 70 },
      { value: "unknown", label: "No sé", weight: 40 },
    ] },
  },
];

const summary = (): Summary => ({
  scanId: 12, started: new Date(Date.now() - 1000 * 60 * 42).toISOString(), type: "Completo",
  verdict: "ProbableInfeccion", verdictText: "Encontramos señales de infección",
  disclaimer: "Ninguna herramienta puede garantizar que una PC esté 100% limpia: un malware muy avanzado (rootkit) puede engañar a cualquier programa. Esto refleja lo que pudimos observar.",
  immediate: "Lo primero: desconectá la PC de internet y no ingreses contraseñas hasta terminar de revisar.",
  scoreMax: 245,
  health: {
    level: "mejorable", summary: "Protección: mejorable. La protección en tiempo real del antivirus está apagada.",
    items: [
      { name: "defender_rtp", label: "Antivirus en tiempo real", ok: false, value: "False" },
      { name: "firewall_private", label: "Firewall (red privada)", ok: true, value: "1" },
      { name: "windows_update_reboot", label: "Windows Update", ok: true, value: "al día" },
      { name: "uac", label: "Control de cuentas (UAC)", ok: true, value: "activado" },
      { name: "rdp", label: "Escritorio remoto", ok: true, value: "desactivado" },
    ],
    issues: [{ name: "defender_rtp", label: "Antivirus en tiempo real", text: "La protección en tiempo real del antivirus está apagada." }],
  },
  defender: { available: true, realTime: false, otherAv: [], recent: [
    { threat: "HackTool:Win64/Mimikatz", time: new Date(Date.now() - 1000 * 60 * 40).toISOString(), paths: [MIMIKATZ], stillPresent: true },
    { threat: "Trojan:Win64/Meterpreter.B", time: new Date(Date.now() - 1000 * 60 * 40).toISOString(), paths: [METERPRETER], stillPresent: true },
  ] },
  counts: { danger: 2, review: 1, questions: 1, processes: 254, startup: 527, connections: 88, extensions: 4, software: 112 },
  findings, collectors: [], feeds: "20261014-1408 (6264 IOCs)",
});

const inventory: Record<string, InventoryRow[]> = {
  startup: [
    { key: "a", name: "WindowsUpdate", detail: "Registro (Run) · HKU\\Lucía\\…\\Run", path: METERPRETER, whatIsIt: "No lo tenemos en nuestra base de conocimiento.", isItNormal: "No. Usa un nombre parecido a Windows Update pero no es de Microsoft y Defender lo identifica como Meterpreter.", status: "danger", score: 245, signer: "sin firma", columns: {} },
    { key: "b", name: "OneDrive", detail: "Registro (Run)", path: "C:\\Users\\Lucía\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", whatIsIt: "Sincronización de archivos de Microsoft. Se instala en tu carpeta de usuario (AppData) a propósito.", isItNormal: "Sí. Que esté en AppData es normal para OneDrive.", status: "ok", score: 0, signer: "Microsoft Corporation", columns: {} },
  ],
};

const diff: DiffReport = {
  previousScanId: 11, previousScanDate: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString(), title: "Novedades desde el último escaneo (martes 13/10 09:12)",
  summary: ["Apareció 1 programa(s) de arranque nuevo(s): WindowsUpdate.", "Apareció 1 extensión(es) nueva(s): PDF Converter Pro.", "Se apagó el antivirus en tiempo real."],
  items: [
    { kind: "Persistence", key: "a", name: "WindowsUpdate", change: "added", detail: `RunKey: ${METERPRETER}`, score: 245 },
    { kind: "Extension", key: "b", name: "PDF Converter Pro", change: "added", detail: "Chrome (Personal) · sideload", score: 30 },
    { kind: "InstalledSoftware", key: "c", name: "Adobe Acrobat Reader", change: "removed", detail: "Adobe 24.1", score: 0 },
  ],
};

const actions: ActionRecord[] = [
  { id: "1", date: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString(), type: "allowlist", target: "x", description: "Listo: marcamos \"Wallpaper Engine\" como reconocido.", reverted: false },
];

const config: Config = {
  onlineHashLookups: true, defenderScanEnabled: true, defenderAvailable: true, virusTotalConfigured: false, abuseChConfigured: false,
  yaraX: { enabled: true, pinned: true, rules: true }, hollowsHunter: { enabled: true, pinned: true }, hayabusa: { enabled: true, pinned: true },
};

const details: Record<string, EntityDetail> = {
  [findings[0].scoringKey]: {
    processTree: [["explorer.exe (4120)", "setup_crack.exe (7712)", "winupdate.exe (9388)"]],
    persistence: [{ type: "RunKey", location: "HKU\\Lucía\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", name: "WindowsUpdate", command: METERPRETER }],
    connections: [{ protocol: "TCP", remoteAddress: "203.0.113.47", remotePort: 4444, state: "Established", tiMatch: "ThreatFox · Metasploit" }],
    attack: findings[0].attackIds,
    binary: { path: METERPRETER, sha256: "4b1e9c07d2a6…f03b77e5a1", size: 7168, reputation: [{ source: "ThreatFox", verdict: "malicious", family: "Metasploit" }, { source: "MalwareBazaar", verdict: "malicious", family: "Meterpreter" }], signature: { isSigned: false, isValid: false, isCatalogSigned: false } },
    findings: [
      { id: "1", heuristicId: "H-32", heuristicName: "Microsoft Defender confirma malware", entityKind: "Binary", entityName: "winupdate.exe", weight: 100, severity: "Critica", attackIds: [], explanation: "", rawData: { threat: "Trojan:Win64/Meterpreter.B" } },
      { id: "2", heuristicId: "H-26", heuristicName: "Match YARA", entityKind: "Binary", entityName: "winupdate.exe", weight: 60, severity: "Alta", attackIds: [], explanation: "", rawData: { rule: "SIGNATURE_BASE_Meterpreter_Reverse_TCP", score: 80 } },
      { id: "3", heuristicId: "H-02", heuristicName: "Conexión a infraestructura maliciosa", entityKind: "Binary", entityName: "winupdate.exe", weight: 50, severity: "Alta", attackIds: ["T1071", "T1571"], explanation: "", rawData: { remote: "203.0.113.47:4444", feed: "ThreatFox" } },
      { id: "4", heuristicId: "H-08", heuristicName: "Persistencia de binario sospechoso", entityKind: "Binary", entityName: "winupdate.exe", weight: 20, severity: "Media", attackIds: ["T1547.001"], explanation: "", rawData: { type: "RunKey", name: "WindowsUpdate" } },
      { id: "5", heuristicId: "H-04", heuristicName: "Ejecución desde carpeta de usuario", entityKind: "Binary", entityName: "winupdate.exe", weight: 15, severity: "Baja", attackIds: [], explanation: "", rawData: { folder: "AppData\\Roaming" } },
    ],
  },
  [findings[1].scoringKey]: {
    processTree: [["winupdate.exe (9388)", "mimikatz.exe (10244)"]],
    persistence: [], connections: [],
    attack: findings[1].attackIds,
    binary: { path: MIMIKATZ, sha256: "e83d5f1a90bc…2c94d0e117", size: 1355264, reputation: [{ source: "CIRCL hashlookup", verdict: "known", family: "mimikatz 2.2.0" }, { source: "MalwareBazaar", verdict: "malicious", family: "Mimikatz" }], signature: { isSigned: false, isValid: false, isCatalogSigned: false }, productName: "mimikatz", companyName: "gentilkiwi (Benjamin DELPY)" },
    findings: [
      { id: "6", heuristicId: "H-32", heuristicName: "Microsoft Defender confirma malware", entityKind: "Binary", entityName: "mimikatz.exe", weight: 100, severity: "Critica", attackIds: [], explanation: "", rawData: { threat: "HackTool:Win64/Mimikatz" } },
      { id: "7", heuristicId: "H-26", heuristicName: "Match YARA", entityKind: "Binary", entityName: "mimikatz.exe", weight: 60, severity: "Alta", attackIds: [], explanation: "", rawData: { rule: "SIGNATURE_BASE_Mimikatz_Strings", score: 85 } },
      { id: "8", heuristicId: "H-31", heuristicName: "Regla Sigma (Hayabusa)", entityKind: "Binary", entityName: "mimikatz.exe", weight: 40, severity: "Alta", attackIds: ["T1003.001"], explanation: "", rawData: { rule: "HackTool - Mimikatz Execution", count: 3, channel: "Microsoft-Windows-Sysmon/Operational" } },
    ],
  },
};
const emptyDetail: EntityDetail = { findings: [], processTree: [], persistence: [], connections: [], attack: [] };

const at = (hhmm: string) => new Date(`2026-10-12T${hhmm}:00-03:00`).toISOString();

const plan: CleanupPlan = {
  scanId: 12, status: "cleanup",
  intro: "Seguí los pasos en orden. Cada acción se puede deshacer desde Actividad.",
  phases: [
    { id: "offline", title: "Desconectá la PC de internet", why: "Así el atacante pierde el control remoto mientras limpiás.", steps: [
      { id: "offline", kind: "manual", title: "Desconectá el cable de red o apagá el Wi-Fi", body: "Tocá el ícono de red abajo a la derecha y apagá el Wi-Fi.", done: false, items: [] },
    ] },
    { id: "stop", title: "Cerrá lo que está corriendo", why: "Un proceso abierto puede volver a crear lo que borres.", steps: [
      { id: "kill_process:a", kind: "action", action: "kill_process", entityKey: findings[0].scoringKey, entityName: "winupdate.exe", title: "Finalizar el programa: winupdate.exe", body: "Es Meterpreter y está conectado a 203.0.113.47.", done: false, items: [] },
    ] },
    { id: "startup", title: "Evitá que vuelva a arrancar solo", why: "Si no, aparece de nuevo al prender la PC.", steps: [
      { id: "disable_startup:a", kind: "action", action: "disable_startup", entityKey: findings[0].scoringKey, entityName: "winupdate.exe", title: "Deshabilitar el arranque automático: winupdate.exe", body: "Arranca solo desde el registro de Windows.", done: true, items: [] },
    ] },
    { id: "quarantine", title: "Aislá los archivos peligrosos", why: "La cuarentena los deja inutilizables sin borrarlos.", steps: [
      { id: "quarantine:a", kind: "action", action: "quarantine", entityKey: findings[0].scoringKey, entityName: "winupdate.exe", title: "Mover a cuarentena: winupdate.exe", body: "Defender lo identifica como Meterpreter.", done: false, items: [] },
      { id: "quarantine:b", kind: "action", action: "quarantine", entityKey: findings[1].scoringKey, entityName: "mimikatz.exe", title: "Mover a cuarentena: mimikatz.exe", body: "Herramienta para robar contraseñas de Windows.", done: false, items: [] },
    ] },
    { id: "defender", title: "Volvé a encender el antivirus", why: "Alguien apagó la protección en tiempo real de Defender.", steps: [
      { id: "defender_rtp", kind: "manual", title: "Activá la protección en tiempo real", body: "Seguridad de Windows → Protección contra virus y amenazas → Administrar la configuración.", done: false, items: [] },
    ] },
    { id: "passwords", title: "Cambiá tus contraseñas desde otro dispositivo", why: "Mimikatz se ejecutó: hay que asumir que tienen tus contraseñas.", steps: [
      { id: "passwords", kind: "passwords", title: "Cambiá las contraseñas desde el celular u otra PC", body: "Empezá por la cuenta de Windows y el mail.", done: false, items: ["Tu cuenta de Windows / Microsoft", "Tu mail principal (Gmail, Outlook…)", "Banco y billeteras virtuales", "Todas las contraseñas guardadas en el navegador"] },
    ] },
    { id: "verify", title: "Verificá que quedó limpio", why: "Un escaneo nuevo confirma que no volvió.", steps: [
      { id: "rescan", kind: "scan", title: "Volvé a escanear", body: "Reiniciá la PC y escaneá de nuevo.", done: false, items: [] },
    ] },
  ],
};

const timeline: Timeline = {
  note: "Ordenamos por fecha lo que Windows registró. Que dos cosas pasen cerca no prueba que una causó la otra; cuando sabemos que se trata del mismo archivo, lo marcamos.",
  episodes: [{ start: at("22:10"), end: at("23:41"), title: "Lunes 12 de octubre, de 22:10 a 23:41", events: [
    { time: at("22:10"), kind: "download", title: "Se descargó setup_crack.exe", detail: "Desde un sitio de descargas, a la carpeta Descargas.", level: "review", entityKey: "crack" },
    { time: at("22:12"), kind: "run", title: "Se ejecutó setup_crack.exe", detail: "Desde Descargas.", level: "review", entityKey: "crack" },
    { time: at("22:13"), kind: "file", title: "Apareció winupdate.exe", detail: "En AppData\\Roaming\\Microsoft\\Windows.", level: "danger", entityKey: findings[0].scoringKey, thread: "m", threadLabel: "winupdate.exe" },
    { time: at("22:13"), kind: "run", title: "Se ejecutó winupdate.exe", detail: "Conexión a 203.0.113.47:4444.", level: "danger", entityKey: findings[0].scoringKey, thread: "m", threadLabel: "winupdate.exe" },
    { time: at("22:47"), kind: "defender", title: "Se apagó la protección en tiempo real de Defender", detail: "Evento 5001 de Microsoft Defender.", level: "danger", entityKey: "defender" },
    { time: at("23:38"), kind: "file", title: "Apareció mimikatz.exe", detail: "En C:\\Users\\Public\\Libraries.", level: "danger", entityKey: findings[1].scoringKey, thread: "k", threadLabel: "mimikatz.exe" },
    { time: at("23:41"), kind: "event", title: "Se ejecutó Mimikatz", detail: "Regla Sigma \"HackTool - Mimikatz Execution\" (3 veces).", level: "danger", entityKey: findings[1].scoringKey, thread: "k", threadLabel: "mimikatz.exe" },
  ] }],
  undated: [{ kind: "startup", title: "winupdate.exe quedó configurado para arrancar solo", detail: "Registro (Run), con el nombre \"WindowsUpdate\".", level: "danger", entityKey: findings[0].scoringKey, thread: "m", threadLabel: "winupdate.exe" }],
};

const sleep =(ms: number) => new Promise((r) => setTimeout(r, ms));

export async function mockCall(op: string, args: Record<string, unknown> | undefined, emit: (e: string, d: unknown) => void): Promise<unknown> {
  await sleep(120);
  switch (op) {
    case "ping": return { version: "dev", elevated: true };
    case "scan.latest": return summary();
    case "findings.list": return findings;
    case "inventory": return inventory[String(args?.tab)] ?? [];
    case "diff": return diff;
    case "plan": return plan;
    case "timeline": return timeline;
    case "action.list": return actions;
    case "allowlist.list": return [];
    case "config.get": return config;
    case "config.set": return config;
    case "entity.detail": return details[String(args?.key)] ?? emptyDetail;
    case "answer": return findings[3];
    case "action.execute": return { success: true, message: "Listo (ejemplo).", actionId: "x", reversible: true };
    case "action.revert": return { success: true, message: "Revertido (ejemplo)." };
    case "feeds.update": return { feeds: "ejemplo", ips: 2924, domains: 2438, hashes: 863 };
    case "scan.start": {
      (async () => {
        for (let p = 5; p <= 100; p += 9) { emit("progress", { stage: "collect", detail: "Revisando (ejemplo)", percent: Math.min(p, 100) }); await sleep(300); }
        emit("scan_done", summary());
      })();
      return { started: true };
    }
    default: throw new Error(`Sin mock para ${op}`);
  }
}
