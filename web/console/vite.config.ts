import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// cythsec 控制台 Vite 配置

// 版本号单一来源：从仓库根 VERSION 文件读取并注入为 __APP_VERSION__ 编译期常量。
//
// 路径从本文件所在目录（web/console）上溯两级到仓库根。此前写的是三级
// （'../../../VERSION'），会解析到仓库**外**的路径，readFileSync 抛异常后被
// catch 静默吞掉、回落 'dev' —— 版本号看起来「有值」，实际从未来自 VERSION。
// 因此这里不再静默兜底：读不到直接让构建失败，避免同类问题再次隐身。
function readRootVersion(): string {
  const file = resolve(__dirname, '../../VERSION');
  try {
    const v = readFileSync(file, 'utf-8').trim();
    if (!v) throw new Error('文件为空');
    return v;
  } catch (err) {
    throw new Error(
      `无法从仓库根读取版本真源 ${file}: ${err instanceof Error ? err.message : String(err)}`,
    );
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
