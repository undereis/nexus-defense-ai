import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Config alinhada ao Tauri: porta fixa 1420 no dev (devUrl do tauri.conf.json).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});
