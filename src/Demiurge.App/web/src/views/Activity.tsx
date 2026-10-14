import { useEffect, useState } from "react";
import { call } from "../bridge";
import { relativeDate } from "../labels";
import type { ActionRecord, ActionResult } from "../types";
import { useToast } from "../components/ui";

export function Activity({ version, onChanged }: { version: number; onChanged: () => void }) {
  const [items, setItems] = useState<ActionRecord[] | null>(null);
  const toast = useToast();
  const load = () => call<ActionRecord[]>("action.list").then(setItems).catch((e) => toast({ text: (e as Error).message, error: true }));
  useEffect(() => { load(); }, [version]); // eslint-disable-line react-hooks/exhaustive-deps

  async function undo(id: string) {
    const r = await call<ActionResult>("action.revert", { id });
    toast({ text: r.message, error: !r.success });
    load();
    onChanged();
  }

  return (
    <section className="view">
      <div className="head">
        <span className="eyebrow">Actividad</span>
        <h1>Lo que hicimos y podés deshacer</h1>
        <p className="sub">Toda acción guarda una copia de lo que cambió. Finalizar un programa es lo único que no se puede deshacer.</p>
      </div>
      {!items && <div className="loading">Cargando…</div>}
      {items && items.length === 0 && <div className="empty">Todavía no hiciste ninguna acción.</div>}
      {items && items.length > 0 && (
        <div>
          {items.map((a) => (
            <div className="tl" key={a.id}>
              <span className="when">{relativeDate(a.date)}</span>
              <span className="mark">•</span>
              <div className="act">
                <span>{a.description}</span>
                {a.reverted ? <span className="mono muted">deshecha</span>
                  : a.type === "kill" ? <span className="mono muted">sin deshacer</span>
                  : <button className="btn small ghost" type="button" onClick={() => undo(a.id)}>Deshacer</button>}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
