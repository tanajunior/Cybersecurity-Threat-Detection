import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './', // <--- CRITICAL: Ensures relative paths for assets in the build
  build: {
    outDir: 'build', // <--- Ensure output is in 'build' directory (Vite default, but good to be explicit)
    assetsDir: 'static', // <--- Optional: Puts generated assets (js, css) into a 'static' subdirectory
  }
})
