import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The API (python -m doppel.cli serve) runs on 8000. In dev, Vite proxies to it; in the demo,
// the API serves the built UI itself, so there is one process and one port.
const API = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": API, "/runs": API, "/fixtures": API },
    // The offline fallback imports the contract's mock verdicts straight from ../contracts/examples.
    fs: { allow: [".."] },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
