import type { EntityScore, InventoryRow } from "./types";

export type Tone = "danger" | "review" | "ask" | "ok";

export const TONE: Record<Tone, { label: string; color: string }> = {
  danger: { label: "Peligroso", color: "var(--danger)" },
  review: { label: "Revisar", color: "var(--review)" },
  ask: { label: "Pregunta", color: "var(--ask)" },
  ok: { label: "Normal", color: "var(--ok)" },
};

export function toneOf(s: EntityScore): Tone {
  if (s.level === "Peligroso") return "danger";
  if (s.level === "Revisar") return "review";
  if (s.pendingQuestion) return "ask";
  return "ok";
}

export function toneOfRow(r: InventoryRow): Tone {
  if (r.status === "danger") return "danger";
  if (r.status === "review") return "review";
  if (r.status === "question") return "ask";
  return "ok";
}

/** Texto del botón, título y explicación de la confirmación, y si se puede deshacer. */
export const ACTIONS: Record<string, { button: string; title: string; body: string; reversible: boolean }> = {
  quarantine: { button: "Mover a cuarentena", title: "Mover a cuarentena", body: "Vamos a guardar el archivo en un lugar seguro donde no puede hacer nada. No se borra: lo podés restaurar desde Actividad.", reversible: true },
  disable_startup: { button: "Deshabilitar arranque", title: "Deshabilitar el arranque", body: "El programa va a dejar de arrancar solo con Windows. Podés volver a activarlo cuando quieras.", reversible: true },
  kill_process: { button: "Finalizar programa", title: "Finalizar el programa", body: "Vamos a cerrar el programa ahora. Esto no se puede deshacer, pero si arranca solo va a volver al reiniciar: conviene también deshabilitar su arranque.", reversible: false },
  remove_extension: { button: "Quitar extensión", title: "Quitar la extensión", body: "Cerrá el navegador antes de continuar. Guardamos una copia por si la querés recuperar.", reversible: true },
  remove_notifications: { button: "Quitar notificaciones", title: "Quitar permisos de notificación", body: "Cerrá el navegador antes de continuar. Los sitios ya no te van a poder mandar notificaciones.", reversible: true },
  restore_browser: { button: "Restaurar navegador", title: "Restaurar buscador y página de inicio", body: "Cerrá el navegador antes de continuar. Volvemos el buscador y la página de inicio a los valores normales.", reversible: true },
  remove_exclusion: { button: "Quitar exclusión", title: "Quitar la exclusión del antivirus", body: "El antivirus va a volver a revisar esa carpeta o programa.", reversible: true },
  restore_hosts: { button: "Restaurar hosts", title: "Restaurar el archivo hosts", body: "Volvemos el archivo hosts a su estado original. Guardamos una copia del actual.", reversible: true },
  restore_proxy: { button: "Quitar proxy", title: "Quitar el proxy", body: "Tu conexión a internet va a dejar de pasar por el proxy configurado. Guardamos la configuración anterior.", reversible: true },
  disable_account: { button: "Deshabilitar cuenta", title: "Deshabilitar la cuenta", body: "Nadie va a poder iniciar sesión con esa cuenta. No se borra: se puede volver a habilitar.", reversible: true },
  remove_certificate: { button: "Quitar certificado", title: "Quitar el certificado", body: "Guardamos una copia por si lo necesitás de nuevo (por ejemplo, si era de tu antivirus o tu trabajo).", reversible: true },
  remove_wmi: { button: "Eliminar tarea oculta", title: "Eliminar la tarea WMI", body: "Borramos la tarea escondida y guardamos una copia.", reversible: true },
  remove_ifeo: { button: "Restaurar función", title: "Restaurar la función de Windows", body: "Quitamos el reemplazo y la función vuelve a funcionar normalmente.", reversible: true },
  allowlist: { button: "Lo reconozco", title: "Marcar como reconocido", body: "No te lo vamos a volver a mostrar como algo para revisar. Podés revertirlo desde Actividad.", reversible: true },
};

export function relativeDate(iso?: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 90) return "recién";
  if (diff < 3600) return `hace ${Math.round(diff / 60)} min`;
  const sameDay = new Date().toDateString() === d.toDateString();
  const time = d.toLocaleTimeString("es-AR", { hour: "2-digit", minute: "2-digit" });
  if (sameDay) return `hoy ${time}`;
  return `${d.toLocaleDateString("es-AR", { weekday: "short", day: "2-digit", month: "2-digit" })} ${time}`;
}
