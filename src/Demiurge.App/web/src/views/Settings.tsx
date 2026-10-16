import { useEffect, useState } from "react";
import { call } from "../bridge";
import { Glossed } from "../components/Glossed";
import type { Config } from "../types";
import { Switch, useToast } from "../components/ui";

// Las claves de VirusTotal son 64 caracteres hexadecimales: así se detecta una clave copiada a medias.
const VT_KEY = /^[0-9a-f]{64}$/i;

export function Settings() {
  const [cfg, setCfg] = useState<Config | null>(null);
  const [vtKey, setVtKey] = useState("");
  const [vtError, setVtError] = useState<string | null>(null);
  const [abuseKey, setAbuseKey] = useState("");
  const [updating, setUpdating] = useState(false);
  const toast = useToast();

  useEffect(() => { call<Config>("config.get").then(setCfg).catch((e) => toast({ text: (e as Error).message, error: true })); }, [toast]);

  async function save(patch: Record<string, unknown>, message = "Guardado."): Promise<boolean> {
    try {
      setCfg(await call<Config>("config.set", patch));
      toast({ text: message });
      return true;
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
      return false;
    }
  }

  async function saveVt() {
    const key = vtKey.trim();
    if (!key) { setVtError("Pegá la clave antes de guardar."); return; }
    if (!VT_KEY.test(key)) { setVtError("Esa clave no parece completa: tiene que ser una tira de 64 letras y números. Copiala de nuevo desde tu perfil en virustotal.com."); return; }
    setVtError(null);
    if (await save({ virusTotalApiKey: key }, "Guardamos la clave. VirusTotal quedó activado.")) setVtKey("");
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
      <div className="head">
        <span className="eyebrow">Ajustes</span>
        <h1>Ajustes</h1>
        <p className="rec-head">Todo viene configurado como recomendamos. Si no sabés qué es una opción, no la toques.</p>
        <p className="sub">Demiurge sólo trabaja mientras está abierto: no deja nada corriendo en segundo plano.</p>
      </div>
      <div className="settings">
        <div className="set">
          <div>
            <strong>Consultas de reputación por hash</strong>
            <p><Glossed text="Preguntamos a CIRCL y MalwareBazaar si un archivo es conocido usando sólo su huella digital (hash). Nunca subimos archivos." max={1} /></p>
          </div>
          <Switch label="Consultas de reputación" checked={cfg.onlineHashLookups} onChange={(v) => save({ onlineHashLookups: v })} />
        </div>

        <div className="set">
          <div>
            <strong>VirusTotal</strong>
            <p>La segunda opinión más completa: más de 70 antivirus revisan cada archivo sospechoso. Necesita una clave gratuita, que se saca en 2 minutos.</p>
            <div className="vt">
              {cfg.virusTotalConfigured ? (
                <>
                  <span className="vt-ok">✓ Clave guardada. En cada escaneo, los archivos sospechosos tienen la opinión de más de 70 antivirus.</span>
                  <button className="link" style={{ justifySelf: "start" }} type="button" onClick={() => save({ virusTotalApiKey: "" }, "Quitamos la clave de VirusTotal.")}>Quitar la clave</button>
                </>
              ) : (
                <>
                  <p className="vt-why"><strong>Suma mucho valor.</strong> Sin VirusTotal, Demiurge reconoce lo que ya está en las listas de amenazas. Con VirusTotal, cada archivo sospechoso lo revisan más de 70 antivirus a la vez: detecta malware nuevo que las listas todavía no tienen y baja las falsas alarmas cuando todos dicen que está limpio.</p>
                  <ol className="vt-steps">
                    {/* Sin link a propósito: la app corre como administrador y el navegador abierto desde acá también lo estaría. */}
                    <li>En el celular o en el navegador, entrá a <span className="mono vt-url selectable">virustotal.com</span> y creá una cuenta gratis (sólo pide un mail).</li>
                    <li>Iniciá sesión, tocá tu nombre arriba a la derecha y elegí <strong>API key</strong>.</li>
                    <li>Copiá la clave: es una tira larga de letras y números.</li>
                    <li>Pegala acá abajo y tocá <strong>Guardar</strong>. Listo.</li>
                  </ol>
                  <div className="vt-form">
                    <input id="vt-key" className="field vt-input" type="password" placeholder="Pegá tu clave de VirusTotal" autoComplete="off" spellCheck={false}
                      value={vtKey} onChange={(e) => { setVtKey(e.target.value); setVtError(null); }} onKeyDown={(e) => { if (e.key === "Enter") saveVt(); }} aria-label="Clave de VirusTotal" />
                    <button className="btn small primary" type="button" onClick={saveVt}>Guardar</button>
                  </div>
                  {vtError && <span className="vt-err">{vtError}</span>}
                  <p className="vt-note">Es gratis: alcanza para unas 500 consultas por día. Sólo enviamos la huella digital (hash) de los archivos sospechosos; nunca subimos tus archivos.</p>
                </>
              )}
            </div>
          </div>
          <span />
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
        <div className="set">
          <div>
            <strong>Inteligencia de amenazas</strong>
            <p>Listas públicas de servidores, dominios y archivos maliciosos (abuse.ch, LOLBAS, LOLDrivers, raíces de Microsoft). Se descargan y se comparan en tu PC; se actualizan solas al abrir la app.</p>
          </div>
          <button className="btn small" type="button" disabled={updating} onClick={updateFeeds}>{updating ? "Actualizando…" : "Actualizar ahora"}</button>
        </div>
        <div className="set">
          <div>
            <strong>Clave de abuse.ch (opcional)</strong>
            <p>MalwareBazaar puede pedir una clave gratuita (auth.abuse.ch). Sin ella, esa consulta se saltea. {cfg.abuseChConfigured ? "Configurada." : "Sin configurar."}</p>
            <div className="inline">
              <input id="abuse-key" className="field" type="password" placeholder="Auth-Key de abuse.ch" value={abuseKey} onChange={(e) => setAbuseKey(e.target.value)} />
              <button className="btn small" type="button" disabled={!abuseKey} onClick={() => { save({ abuseChAuthKey: abuseKey }, "Clave de abuse.ch guardada."); setAbuseKey(""); }}>Guardar</button>
            </div>
          </div>
          <span />
        </div>
      </div>
    </section>
  );
}
