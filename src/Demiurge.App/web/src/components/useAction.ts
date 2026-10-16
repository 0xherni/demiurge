import { useState } from "react";
import { call } from "../bridge";
import type { ActionResult } from "../types";
import { useToast } from "./ui";

/** Ejecutar una acción y una respuesta, con aviso y "Deshacer". Lo comparten la tarjeta y el plan de limpieza. */
export function useEntityActions(onChanged: () => void) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);

  async function run(action: string, entityKey: string) {
    setBusy(true);
    try {
      const r = await call<ActionResult>("action.execute", { action, entityKey, confirmed: true });
      if (!r.success) { toast({ text: r.message, error: true }); return; }
      toast({
        text: r.message,
        undo: r.reversible && r.actionId ? async () => {
          const u = await call<ActionResult>("action.revert", { id: r.actionId });
          toast({ text: u.message, error: !u.success });
          onChanged();
        } : undefined,
      });
      onChanged();
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
    } finally {
      setBusy(false);
    }
  }

  async function answer(entityKey: string, questionId: string, value: string) {
    setBusy(true);
    try {
      await call("answer", { entityKey, questionId, answer: value });
      onChanged();
    } catch (e) {
      toast({ text: (e as Error).message, error: true });
    } finally {
      setBusy(false);
    }
  }

  return { busy, run, answer };
}
