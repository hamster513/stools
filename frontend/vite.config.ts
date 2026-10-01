import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Хешированные файлы сборки — в /static/, не в /assets/: путь /assets/* занят модулем Assets
  // (прямой заход на /assets/list иначе отдавал бы 404 из file_server Caddy).
  build: { assetsDir: 'static' },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
})
