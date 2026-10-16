import { useState, type ReactNode } from "react";
import { TERM_DEFS, TERM_RX } from "../glossary";

/**
 * Texto con las palabras técnicas subrayadas: al pasar el mouse (o con Tab) aparece qué significan.
 * Sólo la primera aparición de cada término y como mucho `max` por texto, para no llenar todo de subrayados.
 */
export function Glossed({ text, max = 3 }: { text: string | undefined | null; max?: number }) {
  if (!text) return null;
  const out: ReactNode[] = [];
  const seen = new Set<string>();
  let last = 0;
  for (const m of text.matchAll(TERM_RX)) {
    const def = TERM_DEFS.get(m[0].toLowerCase());
    if (!def || seen.has(def) || seen.size >= max) continue;
    seen.add(def);
    const at = m.index ?? 0;
    out.push(text.slice(last, at));
    out.push(<Term key={at} word={m[0]} def={def} />);
    last = at + m[0].length;
  }
  if (last === 0) return <>{text}</>;
  out.push(text.slice(last));
  return <>{out}</>;
}

function Term({ word, def }: { word: string; def: string }) {
  // Posición fija calculada al abrir: las tarjetas recortan lo que sobresale (overflow: hidden).
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean } | null>(null);
  const show = (el: HTMLElement) => {
    const r = el.getBoundingClientRect();
    const width = 300;
    const above = r.bottom + 140 > window.innerHeight;
    setPos({ left: Math.max(8, Math.min(r.left, window.innerWidth - width - 8)), top: above ? r.top - 6 : r.bottom + 6, above });
  };
  return (
    <span
      className="term"
      tabIndex={0}
      onMouseEnter={(e) => show(e.currentTarget)}
      onMouseLeave={() => setPos(null)}
      onFocus={(e) => show(e.currentTarget)}
      onBlur={() => setPos(null)}
    >
      {word}
      {pos && (
        <span className="tip" role="tooltip" style={{ left: pos.left, top: pos.top, transform: pos.above ? "translateY(-100%)" : undefined }}>
          <b>{word}</b>{def}
        </span>
      )}
    </span>
  );
}
