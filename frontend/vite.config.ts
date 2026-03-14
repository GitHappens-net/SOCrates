import { defineConfig } from 'vite';
import react from "@vitejs/plugin-react-swc";
import path from 'path';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()].filter(Boolean),
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5174,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        secure: false,
      }
    }
  },
})
