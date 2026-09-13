import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// cythsec 控制台 Vite 配置

// 版本号单一来源：从仓库根 VERSION 文件读取并注入为 __APP_VERSION__ 全局常量。
// 前端代码可在运行时通过 (import.meta as any).env? 之外直接用全局 __APP_VERSION__ 读取。
function readRootVersion(): string {
  try {
    return readFileSync(resolve(__dirname, '../../../VERSION'), 'utf-8').trim();
  } catch {
    return 'dev';
  }
}

// cythsec 控制台 Vite 配置
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(readRootVersion()),
  },
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
