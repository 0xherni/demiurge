import { useEffect, useState } from "react";
import { call } from "../bridge";
import { TONE } from "../labels";
import type { Timeline, TimelineEvent } from "../types";
import { Glossed } from "./Glossed";

const LEVEL_COLOR: Record<TimelineEvent["level"], string> = {
  danger: TONE.danger.color, review: TONE.review.color, question: TONE.ask.color, info: "var(--ash-2)", ok: TONE.ok.color,
};

const KIND_LABEL: Record<string, string> = {
  download: "Descarga", file: "Archivo", run: "Ejecución", command: "Comando", startup: "Arranque", event: "Registro de Windows",
  install: "Instalación", account: "Cuenta", defender: "Antivirus", action: "Demiurge", change: "Cambio",
};

/** "Qué pasó": los hechos con fecha, agrupados por momento, del más reciente al más viejo. */
export function TimelineView({ version, openFinding }: { version: number; openFinding: (key: string) => void }) {
  const [tl, setTl] = useState<Timeline | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<Timeline | null>("timeline").then((t) => { setTl(t); setError(null); }).catch((e) => setError((e as Error).message));
  }, [version]);

  if (error) return <div className="empty">{error}</div>;
  if (!tl) return <div className="loading">Cargando…</div>;
  if (tl.episodes.length === 0 && tl.undated.length === 0)
    return <div className="empty">No hay nada que contar: el último escaneo no encontró nada sospechoso con fecha.</div>;

  // Un hilo se marca sólo si aparece más de una vez: "es el mismo archivo que…".
  const threadCount = new Map<string, number>();
  for (const e of [...tl.episodes.flatMap((ep) => ep.events), ...tl.undated])
    if (e.thread) threadCount.set(e.thread, (threadCount.get(e.thread) ?? 0) + 1);

  const Event = ({ e }: { e: TimelineEvent }) => (
    <li className="tev">
      <span className="tt tnum">{e.time ? new Date(e.time).toLocaleTimeString("es-AR", { hour: "2-digit", minute: "2-digit", hourCycle: "h23" }) : "—"}</span>
      <span className="tdot" style={{ background: LEVEL_COLOR[e.level] }} />
      <div className="tw">
        <span className="tk">{KIND_LABEL[e.kind] ?? e.kind}</span>
        <span className="tn">{e.title}</span>
        {e.detail && <span className="td"><Glossed text={e.detail} max={2} /></span>}
        <span className="tmeta">
          {e.thread && (threadCount.get(e.thread) ?? 0) > 1 && (
            <span className="thread" title="Estos eventos son del mismo archivo">mismo archivo: {e.threadLabel}</span>
          )}
          {e.entityKey && <button className="link" type="button" onClick={() => openFinding(e.entityKey!)}>Ver explicación</button>}
        </span>
      </div>
    </li>
  );

  return (
    <div className="timeline">
      <p className="honest" style={{ borderTop: 0, paddingTop: 0 }}>{tl.note}</p>
      {tl.episodes.map((ep) => (
        <section className="episode" key={ep.start}>
          <h2>{ep.title}</h2>
          <ol className="tlist">{ep.events.map((e, i) => <Event e={e} key={i} />)}</ol>
        </section>
      ))}
      {tl.undated.length > 0 && (
        <section className="episode">
          <h2>Sin fecha</h2>
          <p className="sub" style={{ fontSize: 13 }}>Windows no guarda cuándo pasaron estas cosas, pero están relacionadas con lo que encontramos.</p>
          <ol className="tlist">{tl.undated.map((e, i) => <Event e={e} key={i} />)}</ol>
        </section>
      )}
    </div>
  );
}
