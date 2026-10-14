import { useEffect, useState } from "react";
import { call } from "../bridge";
import type { Config } from "../types";
import { Switch, useToast } from "../components/ui";

export function Settings() {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [vtKey, setVtKey] = useState("");
  const [abuseKey, setAbuseKey] = useState("");
  const [updating, setUpdating] = useState(false);
  const toast = useToast();

  useEffect(() => { call<Config>("config.get").then(setCfg).catch((e) => toast({ text: (e as Error).message, error: true })); }, [toast]);

  async function save(patch: Record<string, unknown>, message = "Guardado.") {
    try {
      setCfg(await call<Config>("config.set", patch));
      toast({ text: message });
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
    }
  }

  async function updateFeeds() {
    setUpdating(true);
    try {
      const r = await call<{ ips: number; domains: number; hashes: number }>("feeds.update");
      toast({ text: `Inteligencia actualizada: ${r.ips + r.domains + r.hashes} indicadores conocidos.` });
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
    } finally {
      setUpdating(false);
    }
  }

  if (!cfg) return <section className="view"><div className="loading">Cargando…</div></section>;

  return (
    <section className="view">
      <div className="head"><span className="eyebrow">Ajustes</span><h1>Ajustes</h1></div>
      <div className="settings">
        <div className="set">
          <div>
            <strong>Consultas de reputación por hash</strong>
            <p>Preguntamos a CIRCL y MalwareBazaar si un archivo es conocido usando sólo su huella digital. Nunca subimos archivos.</p>
          </div>
          <Switch label="Consultas de reputación" checked={cfg.onlineHashLookups} onChange={(v) => save({ onlineHashLookups: v })} />
        </div>
        <div className="set">
          <div>
            <strong>Análisis con Microsoft Defender</strong>
            <p>Cuando encontramos algo sospechoso, le pedimos al motor de Defender que lo analice a fondo para confirmar qué es. Defender no borra nada por su cuenta: la decisión es tuya. {cfg.defenderAvailable ? "" : "Defender no está disponible en esta PC."}</p>
          </div>
          <Switch label="Análisis con Defender" checked={cfg.defenderScanEnabled} disabled={!cfg.defenderAvailable} onChange={(v) => save({ defenderScanEnabled: v })} />
        </div>
        <div className="set">
          <div>
            <strong>VirusTotal</strong>
            <p>Segunda opinión con más de 70 antivirus, también sólo por hash. Necesita tu propia clave gratuita de virustotal.com. {cfg.virusTotalConfigured ? "Configurada." : "Sin configurar."}</p>
            <div className="inline">
              <input id="vt-key" className="field" type="password" placeholder="Clave de API de VirusTotal" value={vtKey} onChange={(e) => setVtKey(e.target.value)} />
              <button className="btn small" type="button" disabled={!vtKey} onClick={() => { save({ virusTotalApiKey: vtKey }, "Clave de VirusTotal guardada."); setVtKey(""); }}>Guardar</button>
              {cfg.virusTotalConfigured && <button className="btn small ghost" type="button" onClick={() => save({ virusTotalApiKey: "" }, "Clave de VirusTotal quitada.")}>Quitar</button>}
            </div>
          </div>
          <span />
        </div>
        <div className="set">
          <div>
            <strong>Clave de abuse.ch</strong>
            <p>MalwareBazaar puede pedir una clave gratuita (auth.abuse.ch). Sin ella, esa consulta se saltea. {cfg.abuseChConfigured ? "Configurada." : "Sin configurar."}</p>
            <div className="inline">
              <input id="abuse-key" className="field" type="password" placeholder="Auth-Key de abuse.ch" value={abuseKey} onChange={(e) => setAbuseKey(e.target.value)} />
              <button className="btn small" type="button" disabled={!abuseKey} onClick={() => { save({ abuseChAuthKey: abuseKey }, "Clave de abuse.ch guardada."); setAbuseKey(""); }}>Guardar</button>
            </div>
          </div>
          <span />
        </div>
        <div className="set">
          <div>
            <strong>Inteligencia de amenazas</strong>
            <p>Listas públicas de servidores, dominios y archivos maliciosos (abuse.ch, LOLBAS, LOLDrivers, raíces de Microsoft). Se descargan y se comparan en tu PC; se actualizan solas al abrir la app.</p>
          </div>
          <button className="btn small" type="button" disabled={updating} onClick={updateFeeds}>{updating ? "Actualizando…" : "Actualizar ahora"}</button>
        </div>
        <div className="set">
          <div>
            <strong>Análisis de contenido (YARA)</strong>
            <p>Busca dentro de los archivos rasgos de miles de familias de malware conocidas (reglas de YARA Forge, se actualizan solas cada semana). {cfg.yaraX.path ? (cfg.yaraX.rules ? "Incluido con Demiurge." : "Incluido; las reglas se descargan la próxima vez que abras la app con internet.") : "No se encontró la herramienta: reinstalá Demiurge."}</p>
          </div>
          <Switch label="YARA" checked={cfg.yaraX.enabled} disabled={!cfg.yaraX.path || !cfg.yaraX.pinned} onChange={(v) => save({ yaraXEnabled: v })} />
        </div>
        <div className="set">
          <div>
            <strong>Análisis de memoria</strong>
            <p>Compara lo que hay en la memoria de los programas con su archivo en el disco, para detectar código escondido dentro de programas legítimos. Revisa los sospechosos en cada escaneo y todos en el escaneo profundo. {cfg.hollowsHunter.path ? "Incluido con Demiurge." : "No se encontró la herramienta: reinstalá Demiurge."}</p>
          </div>
          <Switch label="Análisis de memoria" checked={cfg.hollowsHunter.enabled} disabled={!cfg.hollowsHunter.path || !cfg.hollowsHunter.pinned} onChange={(v) => save({ hollowsHunterEnabled: v })} />
        </div>
        <div className="set">
          <div>
            <strong>Revisión de los registros de eventos (Sigma)</strong>
            <p>Revisa todos los registros de Windows con miles de reglas de la comunidad (Hayabusa): últimos 7 días en cada escaneo, 30 en el profundo. Necesita permisos de administrador. {cfg.hayabusa.path ? "Incluido con Demiurge." : "No se encontró la herramienta: reinstalá Demiurge."}</p>
          </div>
          <Switch label="Revisión de registros" checked={cfg.hayabusa.enabled} disabled={!cfg.hayabusa.path} onChange={(v) => save({ hayabusaEnabled: v })} />
        </div>
      </div>
      <p className="honest">Demiurge no deja nada corriendo en segundo plano: cuando cerrás la ventana, no queda ningún proceso activo. Para revisar la PC de nuevo, abrí la app y escaneá.</p>
    </section>
  );
}
