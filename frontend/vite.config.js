import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// During development (npm run dev) API calls are forwarded to the Flask backend.
export default defineConfig({
  plugins: [react()],
  base: './',
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:5000' } },
  test: { environment: 'jsdom', globals: true, setupFiles: './src/test-setup.js' },
})
