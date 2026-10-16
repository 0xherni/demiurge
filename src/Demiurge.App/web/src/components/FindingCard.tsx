import { useState } from "react";
import { call } from "../bridge";
import { ACTIONS, TONE, toneOf } from "../labels";
import type { EntityDetail, EntityScore } from "../types";
import { Glossed } from "./Glossed";
import { Confirm, useToast } from "./ui";
import { useEntityActions } from "./useAction";

/** Tarjeta de las 4 preguntas (08_UX_Explicaciones) con acciones, pregunta al usuario y detalle técnico. */
export function FindingCard({ item, onChanged }: { item: EntityScore; onChanged: () => void }) {
  const tone = toneOf(item);
  const toast = useToast();
  const [confirm, setConfirm] = useState<string | null>(null);
  const { busy, run, answer: reply } = useEntityActions(onChanged);
  const [detail, setDetail] = useState<EntityDetail | null>(null);

  function runAction(action: string) {
    setConfirm(null);
    run(action, item.scoringKey);
  }

  const answer = (value: string) => reply(item.scoringKey, item.pendingQuestion!.questionId, value);

  async function loadDetail(open: boolean) {
    if (!open || detail) return;
    try { setDetail(await call<EntityDetail>("entity.detail", { key: item.scoringKey })); }
    catch (e) { toast({ text: (e as Error).message, error: true }); }
  }

  const actions = item.availableActions.filter((a) => a !== "allowlist" && ACTIONS[a]);
  const def = confirm ? ACTIONS[confirm] : null;

  return (
    <article className="card" data-level={tone} id={`card-${item.scoringKey}`}>
      <div className="stripe" />
      <div className="card-body">
        <div className="card-top">
          <span className="name">{item.displayName}</span>
          <span className="lvl" style={{ color: TONE[tone].color }}>{TONE[tone].label}</span>
          <span className="score tnum">score {item.score}</span>
          {item.path && <span className="path mono selectable">{item.path}</span>}
        </div>
        <dl className="qa">
          <dt>¿Qué encontramos?</dt><dd><Glossed text={item.whatWeFound} /></dd>
          <dt>¿Por qué?</dt><dd><ul>{item.whyItCaughtOurAttention.map((w, i) => <li key={i}><Glossed text={w} max={2} /></li>)}</ul></dd>
          <dt>¿Qué tan grave es?</dt><dd><Glossed text={item.howSerious} max={1} /></dd>
          <dt>¿Qué hago?</dt><dd><Glossed text={item.whatToDo} max={2} /></dd>
        </dl>
        {item.pendingQuestion && (
          <div className="question">
            <span className="q">{item.pendingQuestion.text}</span>
            <div className="opts">
              {item.pendingQuestion.options.map((o) => (
                <button key={o.value} className="btn small" type="button" disabled={busy} onClick={() => answer(o.value)}>{o.label}</button>
              ))}
            </div>
          </div>
        )}
        <div className="actions">
          {actions.map((a) => (
            <button key={a} className="btn small" type="button" disabled={busy} onClick={() => setConfirm(a)}>{ACTIONS[a].button}</button>
          ))}
          <span className="sep" />
          <button className="btn small ghost" type="button" disabled={busy} onClick={() => setConfirm("allowlist")}>Lo reconozco</button>
        </div>
        <details className="tech" onToggle={(e) => loadDetail((e.target as HTMLDetailsElement).open)}>
          <summary>Ver detalle técnico</summary>
          {!detail ? <div className="loading">Cargando…</div> : <TechDetail detail={detail} />}
        </details>
      </div>
      {def && confirm && (
        <Confirm title={`${def.title}: ${item.displayName}`} body={def.body} onCancel={() => setConfirm(null)} onConfirm={() => runAction(confirm)} />
      )}
    </article>
  );
}

function TechDetail({ detail }: { detail: EntityDetail }) {
  const b = detail.binary;
  const sig = b?.signature;
  return (
    <dl className="techgrid selectable">
      {b && <>
        <dt>Ruta</dt><dd className="mono">{b.path}</dd>
        {b.sha256 && <><dt>SHA256</dt><dd className="mono">{b.sha256}</dd></>}
        <dt>Firma</dt><dd>{sig?.isValid ? `Válida · ${sig.signer ?? ""}${sig.isCatalogSigned ? " (catálogo)" : ""}` : sig?.isSigned ? "Inválida" : "Sin firma"}</dd>
        {b.reputation.length > 0 && <><dt>Reputación</dt><dd>{b.reputation.map((r) => `${r.source}: ${r.verdict}${r.family ? ` (${r.family})` : ""}`).join(" · ")}</dd></>}
      </>}
      {detail.knowledge && <><dt>¿Qué es?</dt><dd>{detail.knowledge.what}</dd></>}
      {detail.processTree.length > 0 && <><dt>Árbol</dt><dd className="mono">{detail.processTree.map((t) => t.join(" → ")).join("  |  ")}</dd></>}
      {detail.persistence.length > 0 && <><dt>Arranque</dt><dd className="mono">{detail.persistence.map((p) => `${p.type} · ${p.location}`).join("\n")}</dd></>}
      {detail.connections.length > 0 && <><dt>Conexiones</dt><dd className="mono">{detail.connections.slice(0, 8).map((c) => `${c.protocol} ${c.remoteAddress ?? ""}:${c.remotePort} ${c.state}${c.tiMatch ? ` · ${c.tiMatch}` : ""}`).join("\n")}</dd></>}
      {detail.findings.length > 0 && <>
        <dt>Señales</dt>
        <dd>{detail.findings.map((f) => (
          <div className="signal" key={f.id}>
            <span>{f.heuristicId} · {f.heuristicName} · peso {f.weight}{f.suppression ? ` (ignorado: ${f.suppression})` : ""}</span>
            <span className="mono raw">{JSON.stringify(f.rawData)}</span>
          </div>
        ))}</dd>
      </>}
      {detail.attack.length > 0 && <><dt>ATT&amp;CK</dt><dd>{detail.attack.map((a) => <span className="tag" key={a}>{a}</span>)}</dd></>}
    </dl>
  );
}
