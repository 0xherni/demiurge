import { useCallback, useEffect, useState } from "react";
import { call, on } from "./bridge";
import { Sigil } from "./components/Eye";
import { Icon } from "./components/Icons";
import { useToast } from "./components/ui";
import { relativeDate } from "./labels";
import type { Progress, Summary } from "./types";
import { Activity } from "./views/Activity";
import { Findings, type FindingsTab } from "./views/Findings";
import { Home } from "./views/Home";
import { Inventory } from "./views/Inventory";
import { News } from "./views/News";
import { Settings } from "./views/Settings";

/** "20261014-1408 (6264 IOCs)" → "Inteligencia: 6.264 indicadores · 14/10 14:08" */
function feedsLabel(raw: string): string {
  const m = raw.match(/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2}) \((\d+) IOCs\)$/);
  if (!m) return "Inteligencia: sin descargar todavía";
  return `Inteligencia: ${Number(m[6]).toLocaleString("es-AR")} indicadores · ${m[3]}/${m[2]} ${m[4]}:${m[5]}`;
}

const NAV: [string, string][] = [["home", "Inicio"], ["findings", "Hallazgos"], ["inventory", "Inventario"], ["news", "Novedades"], ["activity", "Actividad"], ["settings", "Ajustes"]];

export function App() {
  const [view, setView] = useState("home");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [findingsTab, setFindingsTab] = useState<FindingsTab>("cards");
  // Se incrementa cada vez que algo cambia (escaneo, acción, respuesta) para que las pantallas recarguen.
  const [version, setVersion] = useState(0);
  const toast = useToast();

  const refresh = useCallback(async () => {
    try {
      setSummary(await call<Summary | null>("scan.latest"));
      setVersion((v) => v + 1);
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
    }
  }, [toast]);

  useEffect(() => {
    refresh();
    call<{ scanning: boolean; progress?: Progress }>("scan.status").then((s) => { setScanning(s.scanning); if (s.progress) setProgress(s.progress); }).catch(() => {});
    const offs = [
      on("progress", (d) => { setScanning(true); setProgress(d as Progress); }),
      on("scan_done", (d) => {
        setScanning(false);
        setProgress(null);
        setSummary(d as Summary);
        setVersion((v) => v + 1);
        toast({ text: "Escaneo terminado." });
      }),
      on("scan_error", (d) => { setScanning(false); setProgress(null); toast({ text: `El escaneo falló: ${String(d)}`, error: true }); }),
      on("scan_cancelled", () => { setScanning(false); setProgress(null); toast({ text: "Escaneo cancelado." }); }),
    ];
    return () => offs.forEach((off) => off());
  }, [refresh, toast]);

  async function scan(deep: boolean) {
    try {
      setScanning(true);
      setProgress({ stage: "start", detail: "Preparando", percent: 1 });
      setView("home");
      await call("scan.start", { type: deep ? "Profundo" : "Completo" });
    } catch (e) {
      setScanning(false);
      toast({ text: (e as Error).message, error: true });
    }
  }

  const go = (v: string) => { setFocus(null); if (v === "findings") setFindingsTab("cards"); setView(v); document.querySelector(".main")?.scrollTo(0, 0); };
  const openFinding = (key: string) => { setFocus(key); setFindingsTab("cards"); setView("findings"); };
  const openPlan = () => { setFocus(null); setFindingsTab("plan"); setView("findings"); document.querySelector(".main")?.scrollTo(0, 0); };
  const pending = summary ? summary.counts.danger + summary.counts.review + summary.counts.questions : 0;

  return (
    <div className="app">
      <nav className="rail" aria-label="Secciones">
        <div className="brand"><Sigil /><span className="wordmark">DEMIURGE</span></div>
        {NAV.map(([id, label]) => (
          <button key={id} className="nav-btn" type="button" aria-current={view === id ? "page" : undefined} onClick={() => go(id)}>
            <Icon name={id} />{label}
            {id === "findings" && pending > 0 && <span className="count tnum">{pending}</span>}
          </button>
        ))}
        <div className="rail-foot">
          <span>{scanning ? `Escaneando… ${progress?.percent ?? 0}%` : summary ? `Último escaneo: ${relativeDate(summary.started)}` : "Sin escaneos"}</span>
          {summary && <span>{feedsLabel(summary.feeds)}</span>}
        </div>
      </nav>
      <main className="main">
        {view === "home" && <Home summary={summary} scanning={scanning} progress={progress} onScan={scan} go={go} openFinding={openFinding} openPlan={openPlan} />}
        {view === "findings" && <Findings version={version} focus={focus} tab={findingsTab} setTab={setFindingsTab} onChanged={refresh} onScan={() => scan(false)} openFinding={openFinding} />}
        {view === "inventory" && <Inventory version={version} />}
        {view === "news" && <News version={version} />}
        {view === "activity" && <Activity version={version} onChanged={refresh} />}
        {view === "settings" && <Settings />}
      </main>
    </div>
  );
}
