import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The bundle is emitted straight into the Go package that embeds it, so a
// single `make build` produces one self-contained executable.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    assetsDir: 'assets',
  },
  // Relative asset URLs keep the bundle working no matter which path prefix the
  // binary is mounted under (code-server serves it at /proxy/<port>/admin/).
  base: './',
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/login': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
    },
  },
})
