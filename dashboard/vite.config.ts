import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: Vite serves the SPA on 5173 and proxies /api to the BFF (8787), so the
// browser only ever talks to same-origin /api and never sees indexer creds.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8787" },
  },
  build: { outDir: "dist" },
});
