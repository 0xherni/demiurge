// Puente con el motor (C#) a través de WebView2. Cada pedido lleva un id; la respuesta vuelve con el mismo id.
// Los eventos (progreso del escaneo) llegan sin id. Fuera de la app (vite dev en un navegador) se usa un mock.


type Listener = (data: unknown) => void;

interface WebViewHost {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (e: { data: unknown }) => void): void;
}

const host: WebViewHost | undefined = (window as unknown as { chrome?: { webview?: WebViewHost } }).chrome?.webview;
const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
const listeners = new Map<string, Set<Listener>>();

interface Message { id?: string; ok?: boolean; data?: unknown; error?: string; event?: string }

host?.addEventListener("message", (e) => {
  const msg = e.data as Message;
  if (msg.event) {
    listeners.get(msg.event)?.forEach((l) => l(msg.data));
    return;
  }
  if (!msg.id) return;
  const p = pending.get(msg.id);
  if (!p) return;
  pending.delete(msg.id);
  if (msg.ok) p.resolve(msg.data);
  else p.reject(new Error(msg.error ?? "Error del motor"));
});

export const insideApp = host !== undefined;

export function call<T = unknown>(op: string, args?: Record<string, unknown>): Promise<T> {
  if (!host) {
    // Fuera de la app (vite dev en un navegador) se usan datos de ejemplo. En el build de producción esta rama se
    // elimina y los datos de ejemplo no se empaquetan.
    if (!import.meta.env.DEV) return Promise.reject(new Error("Abrí Demiurge desde su acceso directo."));
    return import("./mock").then((m) => m.mockCall(op, args, emit) as Promise<T>);
  }
  const id = crypto.randomUUID();
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    host.postMessage({ id, op, args });
  });
}

export function on(event: string, listener: Listener): () => void {
  if (!listeners.has(event)) listeners.set(event, new Set());
  listeners.get(event)!.add(listener);
  return () => listeners.get(event)?.delete(listener);
}

function emit(event: string, data: unknown) {
  listeners.get(event)?.forEach((l) => l(data));
}
