import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: "0.0.0.0",
    proxy: {
      // Proxy /api/* → http://localhost:8000/* (same rewrite nginx does in Docker)
      // ws:true means Vite will also upgrade WebSocket connections under this path,
      // enabling useSocStream to connect to ws://localhost:5173/api/v1/soc/stream
      // which is transparently proxied to ws://localhost:8000/v1/soc/stream.
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
        ws: true,
      },
    },
  },
});
