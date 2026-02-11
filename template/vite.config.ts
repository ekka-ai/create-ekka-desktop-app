import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { readFileSync } from 'fs'

// Read branding from app.config.json (single source of truth)
const appConfig = JSON.parse(readFileSync(resolve(__dirname, 'app.config.json'), 'utf8'))

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  define: {
    __APP_NAME__: JSON.stringify(appConfig.app.name),
  },
  resolve: {
    alias: {
      '@ekka': resolve(__dirname, 'src/ekka'),
    },
  },

  // Tauri expects a fixed port for dev server
  server: {
    port: 5173,
    strictPort: true,
  },

  // Prevent vite from obscuring Rust errors
  clearScreen: false,

  // Env variables starting with TAURI_ are exposed to the frontend
  envPrefix: ['VITE_', 'TAURI_'],

  build: {
    // Tauri uses Chromium on Windows and WebKit on macOS/Linux
    target: process.env.TAURI_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    // Don't minify for debug builds
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    // Produce sourcemaps for debug builds
    sourcemap: !!process.env.TAURI_DEBUG,
  },
})
