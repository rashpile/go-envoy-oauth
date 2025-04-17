import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true,
    hmr: {
      host: 'localhost'
    },
    proxy: {
      '/oauth': {
        target: 'http://host.docker.internal:8080',
        changeOrigin: true,
      },
    },
    allowedHosts: ['host.docker.internal', 'localhost'],
  },
  preview: {
    port: 3000,
    host: true,
  },
}) 