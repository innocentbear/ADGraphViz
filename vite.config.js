import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Force PostCSS to avoid native lightningcss binding issues on Windows
  css: {
    transformer: 'postcss',
  },
})
