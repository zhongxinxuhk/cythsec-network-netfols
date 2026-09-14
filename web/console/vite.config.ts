import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readRootVersion } from './version-source';

// cythsec 控制台 Vite 配置

// 版本号单一来源：从仓库根 VERSION 文件读取并注入为 __APP_VERSION__ 编译期常量。
// 读取实现见 version-source.ts —— 与 vitest.config.ts 共用同一份，不再各写一遍。
//
// 历史教训（保留在此，因为它值得被记住）：本文件曾写三级上溯 '../../../VERSION'，
// 解析到仓库**外**的路径，readFileSync 抛异常后被 catch 静默吞掉、回落 'dev'，于是
// 版本号看起来「有值」实际从未来自 VERSION。修好本文件时**没有同步**测试侧的那份
// 副本，vitest 继续沿用同一个错误路径，导致 version.test.ts 的两个用例长期红灯 ——
// 而那两个用例的职责恰恰是「证明版本注入链路是通的」。两份副本就是根因。
//
// 因此这里不再静默兜底：读不到直接让构建失败，避免同类问题再次隐身。

// cythsec 控制台 Vite 配置
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(readRootVersion(__dirname)),
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
