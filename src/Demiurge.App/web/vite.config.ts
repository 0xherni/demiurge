import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// La UI se sirve desde una carpeta local mapeada por WebView2 (https://app.demiurge.example/).
// Rutas relativas y todo empaquetado: la app no carga nada de internet.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
