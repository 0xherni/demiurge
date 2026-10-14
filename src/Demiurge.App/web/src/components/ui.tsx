import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

// ---------- Toast ----------

interface ToastState { text: string; error?: boolean; undo?: () => void }
const ToastContext = createContext<(t: ToastState) => void>(() => {});
export const useToast = () => useContext(ToastContext);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<ToastState | null>(null);
  const timer = useRef<number>(0);
  const show = useCallback((t: ToastState) => {
    setToast(t);
    clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), t.undo ? 7000 : 4500);
  }, []);
  return (
    <ToastContext.Provider value={show}>
      {children}
      {toast && (
        <div className={`toast ${toast.error ? "error" : ""}`} role="status">
          <span>{toast.text}</span>
          {toast.undo && <button type="button" onClick={() => { toast.undo!(); setToast(null); }}>Deshacer</button>}
        </div>
      )}
    </ToastContext.Provider>
  );
}

// ---------- Confirmación ----------

export function Confirm({ title, body, confirmLabel = "Confirmar", onConfirm, onCancel }: {
  title: string; body: string; confirmLabel?: string; onConfirm: () => void; onCancel: () => void;
}) {
  const ok = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    ok.current?.focus();
    const esc = (e: KeyboardEvent) => { if (e.key === "Escape") onCancel(); };
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [onCancel]);
  return (
    <div className="scrim" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
      <div className="modal">
        <h2 id="confirm-title">{title}</h2>
        <p>{body}</p>
        <div className="actions">
          <button className="btn ghost" type="button" onClick={onCancel}>Cancelar</button>
          <button className="btn primary" type="button" ref={ok} onClick={onConfirm}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}

export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button className="switch" type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} onClick={() => onChange(!checked)} />
  );
}
