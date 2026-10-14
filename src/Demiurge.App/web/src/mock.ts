// Datos de EJEMPLO para desarrollar la interfaz en un navegador (fuera de la app no hay motor).
// Dentro de la app nunca se usan.

import type { ActionRecord, Config, DiffReport, EntityDetail, EntityScore, InventoryRow, Summary } from "./types";

const findings: EntityScore[] = [
  {
    scoringKey: "9f2c41e07ab3", kind: "Binary", displayName: "svchost.exe", path: "C:\\Users\\Lucía\\AppData\\Roaming\\Microsoft\\svchost.exe",
    score: 114, level: "Peligroso", maxSeverity: "Alta", criticalOverride: false, attackIds: ["T1036.005", "T1071", "T1547"],
    whatWeFound: "Un programa desconocido (\"svchost.exe\") se hace pasar por un proceso de Windows, arranca con tu computadora y habla con un servidor denunciado.",
    whyItCaughtOurAttention: [
      "\"svchost.exe\" usa el nombre de un proceso de Windows pero no está donde Windows guarda sus archivos. Es una técnica típica para pasar desapercibido.",
      "\"svchost.exe\" se está comunicando con 185.215.113.66:443, una dirección que otros ya denunciaron por servidor de control de malware (RedLine Stealer).",
      "\"svchost.exe\" se configuró para arrancar solo cada vez que encendés la PC.",
      "\"svchost.exe\" no tiene firma digital: ningún fabricante se hace responsable de él. Por sí solo no es grave.",
    ],
    howSerious: "Alta (Peligroso). Esconderse con el nombre de un proceso de Windows es un patrón típico de programas que roban datos guardados en el navegador.",
    whatToDo: "Lo primero: desconectá la PC de internet y no ingreses contraseñas hasta terminar de revisar. Revisá el detalle; es una señal fuerte de infección.",
    availableActions: ["quarantine", "disable_startup", "kill_process", "allowlist"],
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
  scoreMax: 114,
  health: {
    level: "mejorable", summary: "Protección: mejorable. Hay actualizaciones de Windows esperando que reinicies la PC.",
    items: [
      { name: "defender_rtp", label: "Antivirus en tiempo real", ok: true, value: "True" },
      { name: "firewall_private", label: "Firewall (red privada)", ok: true, value: "1" },
      { name: "windows_update_reboot", label: "Windows Update", ok: false, value: "reinicio pendiente" },
      { name: "uac", label: "Control de cuentas (UAC)", ok: true, value: "activado" },
      { name: "rdp", label: "Escritorio remoto", ok: true, value: "desactivado" },
    ],
    issues: [{ name: "windows_update_reboot", label: "Windows Update", text: "Hay actualizaciones de Windows esperando que reinicies la PC." }],
  },
  defender: { available: true, realTime: true, otherAv: [], recent: [
    { threat: "Trojan:Win32/Wacatac.B!ml", time: new Date(Date.now() - 1000 * 60 * 60 * 50).toISOString(), paths: ["C:\\Users\\Lucía\\Downloads\\crack.exe"], stillPresent: false },
  ] },
  counts: { danger: 1, review: 1, questions: 1, processes: 254, startup: 527, connections: 88, extensions: 4, software: 112 },
  findings, collectors: [], feeds: "20261014-1408 (6264 IOCs)",
});

const inventory: Record<string, InventoryRow[]> = {
  startup: [
    { key: "a", name: "WindowsHost", detail: "Registro (Run) · HKU\\Lucía\\…\\Run", path: "C:\\Users\\Lucía\\AppData\\Roaming\\Microsoft\\svchost.exe", whatIsIt: "No lo tenemos en nuestra base de conocimiento.", isItNormal: "Tiene el nombre de un programa conocido pero no la firma o ubicación esperadas: revisalo.", status: "danger", score: 114, signer: "sin firma", columns: {} },
    { key: "b", name: "OneDrive", detail: "Registro (Run)", path: "C:\\Users\\Lucía\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", whatIsIt: "Sincronización de archivos de Microsoft. Se instala en tu carpeta de usuario (AppData) a propósito.", isItNormal: "Sí. Que esté en AppData es normal para OneDrive.", status: "ok", score: 0, signer: "Microsoft Corporation", columns: {} },
  ],
};

const diff: DiffReport = {
  previousScanId: 11, previousScanDate: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString(), title: "Novedades desde el último escaneo (martes 13/10 09:12)",
  summary: ["Apareció 1 programa(s) de arranque nuevo(s): WindowsHost.", "Apareció 1 extensión(es) nueva(s): PDF Converter Pro."],
  items: [
    { kind: "Persistence", key: "a", name: "WindowsHost", change: "added", detail: "RunKey: C:\\Users\\Lucía\\AppData\\Roaming\\Microsoft\\svchost.exe", score: 20 },
    { kind: "Extension", key: "b", name: "PDF Converter Pro", change: "added", detail: "Chrome (Personal) · sideload", score: 30 },
    { kind: "InstalledSoftware", key: "c", name: "Adobe Acrobat Reader", change: "removed", detail: "Adobe 24.1", score: 0 },
  ],
};

const actions: ActionRecord[] = [
  { id: "1", date: new Date(Date.now() - 1000 * 60 * 60 * 20).toISOString(), type: "allowlist", target: "x", description: "Listo: marcamos \"Wallpaper Engine\" como reconocido.", reverted: false },
];

const config: Config = {
  onlineHashLookups: true, defenderScanEnabled: true, defenderAvailable: true, virusTotalConfigured: false, abuseChConfigured: false,
  yaraX: { enabled: false, pinned: false }, hollowsHunter: { enabled: false, pinned: false }, hayabusa: { enabled: false, pinned: false },
};

const detail: EntityDetail = {
  findings: [], processTree: [["explorer.exe (4120)", "svchost.exe (9388)"]], persistence: [], connections: [], attack: ["T1036.005", "T1071"],
  binary: { path: findings[0].path!, sha256: "9f2c41e07ab3…d81a0c55e2", size: 482304, reputation: [{ source: "ThreatFox", verdict: "malicious", family: "RedLine Stealer" }], signature: { isSigned: false, isValid: false, isCatalogSigned: false } },
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function mockCall(op: string, args: Record<string, unknown> | undefined, emit: (e: string, d: unknown) => void): Promise<unknown> {
  await sleep(120);
  switch (op) {
    case "ping": return { version: "dev", elevated: false };
    case "scan.latest": return summary();
    case "findings.list": return findings;
    case "inventory": return inventory[String(args?.tab)] ?? [];
    case "diff": return diff;
    case "action.list": return actions;
    case "allowlist.list": return [];
    case "config.get": return config;
    case "config.set": return config;
    case "entity.detail": return detail;
    case "answer": return findings[2];
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
