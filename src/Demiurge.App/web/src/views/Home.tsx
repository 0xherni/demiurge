import { useEffect, useState, type ReactNode } from "react";
import { call } from "../bridge";
import { EyeBig } from "../components/Eye";
import { TONE, relativeDate, toneOf } from "../labels";
import type { DiffReport, Progress, Summary } from "../types";

/** Recuadro de sección: título, una línea que explica qué muestra y, opcionalmente, una acción. */
function Box({ title, description, action, tone, children }: {
  title: string; description: string; action?: ReactNode; tone?: string; children: ReactNode;
}) {
  return (
    <section className="box" style={tone ? { borderTopColor: tone } : undefined}>
      <header className="box-head">
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        {action}
      </header>
      <div className="box-body">{children}</div>
    </section>
  );
}

/** Lo que Defender ya detectó: resuelto (en verde) o con el archivo todavía presente (en rojo). */
function DefenderPanel({ defender }: { defender: NonNullable<Summary["defender"]> }) {
  const pending = defender.recent.filter((d) => d.stillPresent);
  return (
    <Box title="Microsoft Defender" description="El antivirus de Windows: si está activo y qué detectó en los últimos 30 días.">
      <div className="health">
        <div>
          <span>Protección en tiempo real</span>
          <span style={{ fontSize: 12, color: defender.realTime ? "var(--ok)" : defender.otherAv.length ? "var(--ash)" : "var(--review)" }}>
            {defender.realTime ? "Activa" : defender.otherAv.length ? `Usás ${defender.otherAv[0]}` : "Apagada"}
          </span>
        </div>
        {defender.recent.length === 0 && <div><span className="muted">No detectó amenazas en los últimos 30 días.</span><span /></div>}
        {defender.recent.slice(0, 5).map((d, i) => (
          <div key={i} title={d.paths.join("\n")}>
            <span>{d.threat}<br /><span className="muted" style={{ fontSize: 12 }}>{relativeDate(d.time)}</span></span>
            <span style={{ fontSize: 12, color: d.stillPresent ? "var(--danger)" : "var(--ok)" }}>{d.stillPresent ? "Sigue en tu PC" : "Resuelta"}</span>
          </div>
        ))}
      </div>
      {pending.length > 0 && <p className="sub" style={{ fontSize: 13 }}>Hay {pending.length} amenaza(s) que Defender detectó pero siguen en tu PC: están en Hallazgos.</p>}
    </Box>
  );
}

/** Primero lo que conviene mejorar (con la explicación); lo que está bien, plegado. */
function HealthList({ items }: { items: Summary["health"]["items"] }) {
  const [open, setOpen] = useState(false);
  const bad = items.filter((h) => h.ok === false);
  const rest = items.filter((h) => h.ok !== false);
  return (
    <>
      <div className="health">
        {bad.map((h) => (
          <div key={h.name}>
            <span>{h.label}<br /><span className="muted" style={{ fontSize: 12 }}>{h.text}</span></span>
            <span style={{ fontSize: 12, color: "var(--review)" }}>Mejorable</span>
          </div>
        ))}
        {bad.length === 0 && <div><span>Todas las protecciones están activas.</span><span style={{ fontSize: 12, color: "var(--ok)" }}>Bien</span></div>}
        {open && rest.map((h) => (
          <div key={h.name}>
            <span>{h.label}</span>
            <span style={{ fontSize: 12, color: h.ok ? "var(--ok)" : "var(--ash)" }}>{h.ok ? "Bien" : "No disponible"}</span>
          </div>
        ))}
      </div>
      {rest.length > 0 && (
        <button className="link" style={{ justifySelf: "start" }} type="button" onClick={() => setOpen(!open)}>
          {open ? "Ocultar" : `Ver ${rest.length === 1 ? "la que está bien" : `las ${rest.length} que están bien`}`}
        </button>
      )}
    </>
  );
}

const VERDICT_TONE = { Limpio: "ok", Revisar: "review", ProbableInfeccion: "danger" } as const;
const VERDICT_LABEL = { Limpio: "Limpio", Revisar: "Revisar", ProbableInfeccion: "Probable infección" } as const;

export function Home({ summary, scanning, progress, onScan, go, openFinding }: {
  summary: Summary | null;
  scanning: boolean;
  progress: Progress | null;
  onScan: (deep: boolean) => void;
  go: (view: string) => void;
  openFinding: (key: string) => void;
}) {
  const [diff, setDiff] = useState<DiffReport | null>(null);
  useEffect(() => {
    if (!summary) return;
    call<DiffReport>("diff").then(setDiff).catch(() => setDiff(null));
  }, [summary]);

  const tone = summary ? VERDICT_TONE[summary.verdict] : "ok";
  const color = TONE[tone].color;
  const attention = (summary?.findings ?? []).slice(0, 4);
  const added = diff?.items.filter((i) => i.change === "added") ?? [];

  return (
    <section className="view">
      <div className="verdict">
        <EyeBig scanning={scanning} />
        <div>
          {scanning ? (
            <>
              <div className="state" style={{ color: "var(--ash)" }}>Escaneando</div>
              <h1>Revisando tu PC…</h1>
              <div className="progress">
                <div className="bar"><i style={{ width: `${progress?.percent ?? 2}%` }} /></div>
                <div className="step"><span>{progress?.detail ?? "Preparando"}</span><span className="tnum">{progress?.percent ?? 0}%</span></div>
              </div>
            </>
          ) : summary ? (
            <>
              <div className="state" style={{ color }}>{VERDICT_LABEL[summary.verdict]}</div>
              <h1>{summary.verdictText}</h1>
              <div className="when">
                Último escaneo: {relativeDate(summary.started)} · {summary.counts.processes} procesos, {summary.counts.startup} entradas de arranque, {summary.counts.extensions} extensiones
              </div>
              {summary.immediate && <p className="alert-line">{summary.immediate}</p>}
              {summary.elevatedWarning && <p className="warn-line">{summary.elevatedWarning}</p>}
              <div className="cta-row">
                <button className="btn primary" type="button" onClick={() => onScan(false)}>Escanear ahora</button>
                <button className="btn" type="button" onClick={() => onScan(true)}>Escaneo profundo</button>
                {summary.findings.length > 0 && <button className="btn ghost" type="button" onClick={() => go("findings")}>Ver hallazgos</button>}
              </div>
            </>
          ) : (
            <>
              <div className="state" style={{ color: "var(--ash)" }}>Sin escanear</div>
              <h1>Todavía no revisamos tu PC</h1>
              <p className="sub">El primer escaneo tarda unos minutos. Revisa programas, arranque, conexiones, navegadores y configuración, y te explica todo lo que encuentra.</p>
              <div className="cta-row"><button className="btn primary" type="button" onClick={() => onScan(false)}>Escanear ahora</button></div>
            </>
          )}
        </div>
      </div>

      {summary && !scanning && (
        <>
          <div className="strip">
            <div><span className="k">Peligroso</span><span className="v tnum" style={{ color: summary.counts.danger ? "var(--danger)" : undefined }}>{summary.counts.danger}</span><span className="d">entidades</span></div>
            <div><span className="k">Para revisar</span><span className="v tnum" style={{ color: summary.counts.review ? "var(--review)" : undefined }}>{summary.counts.review}</span><span className="d">entidades</span></div>
            <div><span className="k">Preguntas</span><span className="v tnum" style={{ color: summary.counts.questions ? "var(--ask)" : undefined }}>{summary.counts.questions}</span><span className="d">esperan tu respuesta</span></div>
            <div>
              <span className="k">Protección</span>
              <span className="v" style={{ fontSize: 17, paddingTop: 4, color: summary.health.level === "buena" ? "var(--ok)" : "var(--review)" }}>{summary.health.level === "buena" ? "Buena" : "Mejorable"}</span>
              <span className="d">{summary.health.issues.length ? `${summary.health.issues.length} punto(s) para mejorar` : "todo en orden"}</span>
            </div>
          </div>

          <div className="two">
            <Box
              title="Lo que necesita tu atención"
              description="Programas y configuraciones con señales sospechosas, de lo más grave a lo menos grave. Tocá uno para ver la explicación completa."
              tone={attention.length ? (summary.counts.danger ? "var(--danger)" : "var(--review)") : "var(--ok)"}
              action={attention.length > 0 ? <button className="link" type="button" onClick={() => go("findings")}>Ver todo</button> : undefined}
            >
              {attention.length ? (
                <div className="mini">
                  {attention.map((f) => {
                    const t = toneOf(f);
                    return (
                      <button type="button" key={f.scoringKey} onClick={() => openFinding(f.scoringKey)}>
                        <span className="dot" style={{ background: TONE[t].color }} />
                        <span><span className="n">{f.displayName}</span><br /><span className="w">{f.whatWeFound}</span></span>
                        <span className="lvl" style={{ color: TONE[t].color }}>{TONE[t].label}</span>
                      </button>
                    );
                  })}
                </div>
              ) : <p className="sub">Nada pendiente: no encontramos nada que necesite tu atención.</p>}
            </Box>
            <div className="stack">
              <Box
                title="Salud del sistema"
                description="Cómo están configuradas las protecciones de Windows. No indica si hay una infección: indica qué tan protegida está la PC."
                tone={summary.health.level === "buena" ? "var(--ok)" : "var(--review)"}
              >
                <HealthList items={summary.health.items} />
              </Box>
              {summary.defender && <DefenderPanel defender={summary.defender} />}
              {diff?.previousScanDate && (
                <Box
                  title="Novedades"
                  description={`Qué apareció en tu PC desde el escaneo anterior (${relativeDate(diff.previousScanDate)}).`}
                  action={added.length > 0 ? <button className="link" type="button" onClick={() => go("news")}>Ver todo</button> : undefined}
                >
                  <p className="sub" style={{ fontSize: 13 }}>{added.length ? diff.summary.join(" ") : "No apareció nada nuevo."}</p>
                </Box>
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
