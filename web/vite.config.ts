import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// The build output goes to web/dist, which fluxgate-admin embeds into the
// binary via rust-embed. During `npm run dev`, /rpc is proxied to the running
// Rust admin server (default 127.0.0.1:8080).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      // The Rust admin server is HTTPS (self-signed) — target https and skip
      // cert verification so `npm run dev` reaches it.
      '/rpc': { target: 'https://127.0.0.1:8080', changeOrigin: true, secure: false },
      '/health': { target: 'https://127.0.0.1:8080', changeOrigin: true, secure: false },
    },
  },
})
