import { useEffect, useState } from "react";
import { call } from "../bridge";
import { TONE, toneOfRow } from "../labels";
import type { InventoryRow } from "../types";

const TABS: [string, string][] = [
  ["startup", "Arranque"], ["processes", "Procesos"], ["connections", "Conexiones"], ["extensions", "Extensiones"],
  ["software", "Programas"], ["accounts", "Cuentas"], ["certificates", "Certificados"], ["drivers", "Controladores"],
  ["files", "Archivos recientes"], ["settings", "Configuración"],
];

export function Inventory({ version }: { version: number }) {
  const [tab, setTab] = useState("startup");
  const [rows, setRows] = useState<InventoryRow[] | null>(null);
  const [search, setSearch] = useState("");
  const [onlyAbnormal, setOnlyAbnormal] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setRows(null);
    call<InventoryRow[]>("inventory", { tab }).then((r) => { setRows(r); setError(null); }).catch((e) => setError((e as Error).message));
  }, [tab, version]);

  const q = search.trim().toLowerCase();
  const visible = (rows ?? []).filter((r) =>
    (!onlyAbnormal || r.status !== "ok") &&
    (!q || `${r.name} ${r.detail ?? ""} ${r.path ?? ""}`.toLowerCase().includes(q)));

  return (
    <section className="view">
      <div className="head">
        <span className="eyebrow">Inventario</span>
        <h1>Todo lo que hay en tu PC</h1>
        <p className="sub">Cada elemento con su explicación. Lo que parece raro pero es normal también se aclara.</p>
      </div>
      <div className="tabs" role="tablist">
        {TABS.map(([k, l]) => <button key={k} className="tab" role="tab" type="button" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
      </div>
      <div className="toolbar">
        <input id="inv-search" className="search" type="search" placeholder="Buscar por nombre o ruta" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Buscar en el inventario" />
        <label className="check"><input id="inv-abnormal" type="checkbox" checked={onlyAbnormal} onChange={(e) => setOnlyAbnormal(e.target.checked)} /> Sólo lo que no es normal</label>
      </div>
      {error && <div className="empty">{error}</div>}
      {!rows && !error && <div className="loading">Cargando…</div>}
      {rows && (
        <div>
          {visible.length === 0 && <p className="sub" style={{ padding: "14px 0" }}>No hay elementos que coincidan.</p>}
          {visible.slice(0, 400).map((r) => {
            const t = toneOfRow(r);
            return (
              <div className="row" key={r.key}>
                <span className="dot" style={{ background: r.status === "info" ? "var(--ash-2)" : TONE[t].color }} />
                <div>
                  <div className="rn">{r.name}</div>
                  {r.detail && <div className="rd">{r.detail}</div>}
                  {r.path && <div className="rd mono selectable">{r.path}{r.signer ? `  ·  ${r.signer}` : ""}</div>}
                </div>
                <div className="ex">
                  <span><b>¿Qué es?</b>{r.whatIsIt}</span>
                  <span><b>¿Es normal?</b>{r.isItNormal}</span>
                </div>
              </div>
            );
          })}
          {visible.length > 400 && <p className="sub" style={{ padding: "14px 0" }}>Mostramos los primeros 400 de {visible.length}. Usá el buscador para encontrar algo puntual.</p>}
        </div>
      )}
    </section>
  );
}
