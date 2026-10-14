import { useEffect, useState } from "react";
import { call } from "../bridge";
import { FindingCard } from "../components/FindingCard";
import { toneOf, type Tone } from "../labels";
import type { EntityScore } from "../types";

const FILTERS: [Tone | "all", string][] = [["all", "Todos"], ["danger", "Peligroso"], ["review", "Revisar"], ["ask", "Preguntas"]];

export function Findings({ version, focus, onChanged }: { version: number; focus: string | null; onChanged: () => void }) {
  const [items, setItems] = useState<EntityScore[] | null>(null);
  const [filter, setFilter] = useState<Tone | "all">("all");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    call<EntityScore[]>("findings.list").then((r) => { setItems(r); setError(null); }).catch((e) => setError((e as Error).message));
  }, [version]);

  useEffect(() => {
    if (!focus || !items) return;
    requestAnimationFrame(() => document.getElementById(`card-${focus}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }, [focus, items]);

  const list = (items ?? []).filter((f) => filter === "all" || toneOf(f) === filter);

  return (
    <section className="view">
      <div className="head">
        <span className="eyebrow">Hallazgos</span>
        <h1>Lo que encontramos, explicado</h1>
        <p className="sub">Cada tarjeta junta todas las señales sobre un mismo programa. Una señal sola pesa poco; varias juntas pesan mucho.</p>
      </div>
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
    </section>
  );
}
