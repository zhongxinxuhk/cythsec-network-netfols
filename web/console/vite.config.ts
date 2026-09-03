import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// cythsec 控制台 Vite 配置
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // 开发期代理到 routerd（默认 :8080，可用 VITE_ROUTERD_TARGET 覆盖）
      '/api': process.env.VITE_ROUTERD_TARGET || 'http://localhost:8080',
      '/healthz': process.env.VITE_ROUTERD_TARGET || 'http://localhost:8080',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
