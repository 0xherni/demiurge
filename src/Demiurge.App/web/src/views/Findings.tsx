import { useEffect, useState } from "react";
import { call } from "../bridge";
import { FindingCard } from "../components/FindingCard";
import { Plan } from "../components/Plan";
import { TimelineView } from "../components/TimelineView";
import { toneOf, type Tone } from "../labels";
import type { EntityScore } from "../types";

const FILTERS: [Tone | "all", string][] = [["all", "Todos"], ["danger", "Peligroso"], ["review", "Revisar"], ["ask", "Preguntas"]];

export type FindingsTab = "cards" | "plan" | "timeline";
const TABS: [FindingsTab, string][] = [["cards", "Tarjetas"], ["plan", "Plan de limpieza"], ["timeline", "Qué pasó"]];

const HEAD: Record<FindingsTab, { title: string; sub: string }> = {
  cards: { title: "Lo que encontramos, explicado", sub: "Cada tarjeta junta todas las señales sobre un mismo programa. Una señal sola pesa poco; varias juntas pesan mucho." },
  plan: { title: "Qué hacer, paso a paso", sub: "Las tarjetas convertidas en pasos ordenados: primero lo que corta el daño, después lo que evita que vuelva. Pasá el mouse por las palabras subrayadas para ver qué significan." },
  timeline: { title: "Qué pasó y cuándo", sub: "Lo que Windows registró sobre lo que encontramos, ordenado por fecha y agrupado por momento." },
};

export function Findings({ version, focus, tab, setTab, onChanged, onScan, openFinding }: {
  version: number; focus: string | null; tab: FindingsTab; setTab: (t: FindingsTab) => void;
  onChanged: () => void; onScan: () => void; openFinding: (key: string) => void;
}) {
  const [items, setItems] = useState<EntityScore[] | null>(null);
  const [filter, setFilter] = useState<Tone | "all">("all");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<EntityScore[]>("findings.list").then((r) => { setItems(r); setError(null); }).catch((e) => setError((e as Error).message));
  }, [version]);

  useEffect(() => {
    if (!focus || !items || tab !== "cards") return;
    requestAnimationFrame(() => document.getElementById(`card-${focus}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, [focus, items, tab]);

  const list = (items ?? []).filter((f) => filter === "all" || toneOf(f) === filter);

  return (
    <section className="view">
      <div className="head">
        <span className="eyebrow">Hallazgos</span>
        <h1>{HEAD[tab].title}</h1>
        <p className="sub">{HEAD[tab].sub}</p>
      </div>
      <div className="tabs" role="tablist">
        {TABS.map(([k, l]) => <button key={k} className="tab" role="tab" type="button" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
      </div>
      {tab === "plan" && <Plan version={version} onChanged={onChanged} onScan={onScan} openFinding={openFinding} />}
      {tab === "timeline" && <TimelineView version={version} openFinding={openFinding} />}
      {tab === "cards" && (
        <>
          <div className="filters">
            {FILTERS.map(([k, l]) => <button key={k} className="pill" type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}>{l}</button>)}
          </div>
          {error && <div className="empty">{error}</div>}
          {!items && !error && <div className="loading">Cargando…</div>}
          {items && (
            <div className="cards">
              {list.length ? list.map((f) => <FindingCard key={f.scoringKey} item={f} onChanged={onChanged} />)
                : <div className="empty">{items.length ? "No hay hallazgos en esta categoría." : "No hay nada para revisar. Seguimos atentos en el próximo escaneo."}</div>}
            </div>
          )}
        </>
      )}
    </section>
  );
}
