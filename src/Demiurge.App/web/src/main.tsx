import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/unbounded";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./styles.css";
import { App } from "./App";
import { ToastProvider } from "./components/ui";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ToastProvider>
      <App />
    </ToastProvider>
  </StrictMode>,
);
