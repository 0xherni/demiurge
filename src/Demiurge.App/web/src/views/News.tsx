import { useEffect, useState } from "react";
import { call } from "../bridge";
import { relativeDate } from "../labels";
import type { DiffReport } from "../types";

const KIND: Record<string, string> = {
  Persistence: "Programa de arranque", InstalledSoftware: "Programa instalado", Extension: "Extensión", Account: "Cuenta",
  Certificate: "Certificado", Driver: "Controlador", SystemSetting: "Configuración", BrowserSetting: "Navegador", FirewallRule: "Regla de firewall",
};

export function News({ version }: { version: number }) {
  const [diff, setDiff] = useState<DiffReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { call<DiffReport>("diff").then(setDiff).catch((e) => setError((e as Error).message)); }, [version]);

  return (
    <section className="view">
      <div className="head">
        <span className="eyebrow">Novedades</span>
        <h1>Qué cambió desde el último escaneo</h1>
        <p className="sub">Comparamos cada escaneo con el anterior: programas de arranque, programas instalados, extensiones, cuentas, certificados y configuración.</p>
      </div>
      {error && <div className="empty">{error}</div>}
      {diff && !diff.previousScanDate && <div className="empty">Hace falta un segundo escaneo para poder comparar.</div>}
      {diff?.previousScanDate && (
        <div>
          {diff.items.length === 0 && <p className="sub">No apareció ni desapareció nada desde {relativeDate(diff.previousScanDate)}.</p>}
          {[...diff.items].sort((a, b) => (a.change === b.change ? b.score - a.score : a.change === "added" ? -1 : 1)).map((i) => (
            <div className="tl" key={`${i.kind}|${i.key}|${i.change}`}>
              <span className="when">{i.change === "added" ? "Apareció" : "Ya no está"}</span>
              <span className={`mark ${i.change === "added" ? "add" : "rem"}`}>{i.change === "added" ? "+" : "−"}</span>
              <div className="what">
                <strong>{KIND[i.kind] ?? i.kind}: {i.name}</strong>
                {i.detail && <span className="mono selectable">{i.detail}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
