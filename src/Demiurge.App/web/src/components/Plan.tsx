import { useEffect, useState } from "react";
import { call } from "../bridge";
import { ACTIONS } from "../labels";
import type { CleanupPlan, PlanStep } from "../types";
import { Glossed } from "./Glossed";
import { Confirm } from "./ui";
import { useEntityActions } from "./useAction";

// Los pasos manuales ("desconectá internet", cada contraseña cambiada) los tilda la persona; se recuerdan por escaneo
// en este equipo. Los pasos con botón se marcan solos cuando la acción quedó registrada.
function loadChecks(scanId: number): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(`demiurge.plan.${scanId}`) ?? "{}"); } catch { return {}; }
}
function saveChecks(scanId: number, checks: Record<string, boolean>) {
  try { localStorage.setItem(`demiurge.plan.${scanId}`, JSON.stringify(checks)); } catch { /* sin almacenamiento: sólo dura la sesión */ }
}

/** Plan de limpieza guiado: las tarjetas convertidas en pasos ordenados, con su botón o su casilla. */
export function Plan({ version, onChanged, onScan, openFinding }: {
  version: number; onChanged: () => void; onScan: () => void; openFinding: (key: string) => void;
}) {
  const [plan, setPlan] = useState<CleanupPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checks, setChecks] = useState<Record<string, boolean>>({});
  const [confirm, setConfirm] = useState<PlanStep | null>(null);
  const { busy, run, answer } = useEntityActions(onChanged);

  useEffect(() => {
    call<CleanupPlan | null>("plan").then((p) => { setPlan(p); setError(null); if (p) setChecks(loadChecks(p.scanId)); })
      .catch((e) => setError((e as Error).message));
  }, [version]);

  if (error) return <div className="empty">{error}</div>;
  if (!plan) return <div className="loading">Cargando…</div>;
  if (plan.status === "clean") return <div className="empty">{plan.intro}</div>;

  const toggle = (id: string) => {
    const next = { ...checks, [id]: !checks[id] };
    setChecks(next);
    saveChecks(plan.scanId, next);
  };
  const isDone = (st: PlanStep) => st.done || !!checks[st.id];
  // El paso final (volver a escanear) no cuenta para el progreso: es la verificación.
  const countable = plan.phases.flatMap((p) => p.steps).filter((s) => s.kind !== "scan");
  const doneCount = countable.filter(isDone).length;
  const def = confirm?.action ? ACTIONS[confirm.action] : null;

  return (
    <div className="plan">
      <div className="plan-head">
        <p className="sub"><Glossed text={plan.intro} /></p>
        <div className="progress" style={{ marginTop: 0 }}>
          <div className="bar"><i style={{ width: `${countable.length ? (doneCount / countable.length) * 100 : 0}%` }} /></div>
          <div className="step"><span>{doneCount === countable.length ? "Hiciste todos los pasos. Falta verificar." : "Tu avance"}</span><span className="tnum">{doneCount} de {countable.length}</span></div>
        </div>
      </div>

      {plan.phases.map((phase, i) => (
        <section className="phase" key={phase.id}>
          <header>
            <span className="num tnum">{i + 1}</span>
            <div>
              <h2>{phase.title}</h2>
              <p><Glossed text={phase.why} max={2} /></p>
            </div>
          </header>
          <div className="steps">
            {phase.steps.map((st) => (
              <div className="pstep" data-done={isDone(st)} key={st.id}>
                <span className="tick" aria-hidden="true">{isDone(st) ? "✓" : ""}</span>
                <div className="pbody">
                  <span className="pt">{st.title}</span>
                  {st.body && <span className="pd"><Glossed text={st.body} max={2} /></span>}
                  {st.kind === "passwords" && (
                    <ul className="plist">
                      {st.items.map((it) => {
                        const id = `${st.id}:${it}`;
                        return (
                          <li key={it}>
                            <label className="check"><input type="checkbox" checked={!!checks[id]} onChange={() => toggle(id)} /> {it}</label>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {st.kind === "questions" && st.options && st.entityKey && (
                    <div className="opts">
                      {st.options.map((o) => (
                        <button key={o.value} className="btn small" type="button" disabled={busy} onClick={() => answer(st.entityKey!, st.questionId!, o.value)}>{o.label}</button>
                      ))}
                    </div>
                  )}
                </div>
                <div className="pact">
                  {st.kind === "action" && st.action && ACTIONS[st.action] && (
                    st.done ? <span className="muted" style={{ fontSize: 12 }}>Hecho</span>
                      : <button className="btn small" type="button" disabled={busy} onClick={() => setConfirm(st)}>{ACTIONS[st.action].button}</button>
                  )}
                  {st.kind === "action" && st.level === "review" && !st.done && (
                    <button className="btn small ghost" type="button" disabled={busy} onClick={() => setConfirm({ ...st, action: "allowlist" })}>Lo reconozco</button>
                  )}
                  {(st.kind === "manual") && (
                    <button className="btn small ghost" type="button" onClick={() => toggle(st.id)}>{checks[st.id] ? "Desmarcar" : "Listo"}</button>
                  )}
                  {st.kind === "passwords" && (
                    <button className="btn small ghost" type="button" onClick={() => toggle(st.id)}>{checks[st.id] ? "Desmarcar" : "Terminé"}</button>
                  )}
                  {st.kind === "scan" && <button className="btn small primary" type="button" onClick={onScan}>Escanear de nuevo</button>}
                  {st.entityKey && st.kind !== "questions" && (
                    <button className="link" type="button" onClick={() => openFinding(st.entityKey!)}>Ver explicación</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}

      {confirm && def && (
        <Confirm title={`${def.title}: ${confirm.entityName ?? ""}`} body={def.body} onCancel={() => setConfirm(null)}
          onConfirm={() => { const st = confirm; setConfirm(null); run(st.action!, st.entityKey!); }} />
      )}
    </div>
  );
}
