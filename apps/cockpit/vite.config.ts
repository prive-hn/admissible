/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const API_TARGET = process.env.FCD_API ?? "http://localhost:8791";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5273,
    proxy: {
      // Dev-only convenience: forward the cockpit API to a local server.
      "/api": {
        target: API_TARGET,
        changeOrigin: true,
        // The server refuses any request whose Origin is not the Host it was
        // reached on. `changeOrigin` rewrites Host but forwards the browser's
        // Origin, so without this the dev server 403s every write. A proxy
        // hop is server-to-server; it presents itself, not the page.
        configure: (proxy) => {
          proxy.on("proxyReq", (req) => req.setHeader("origin", API_TARGET));
        },
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    css: false,
    include: ["tests/**/*.test.{ts,tsx}"],
  },
});
