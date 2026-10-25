import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readRootVersion } from './version-source';

// 与 vite.config.ts 共用同一条版本注入路径（实现见 version-source.ts）。
//
// 测试若不注入 __APP_VERSION__，测到的就只是降级值 'dev'，无法验证
// 「版本号来自仓库根 VERSION」这件事本身 —— 而 version.test.ts 的全部价值就在于
// 证明这条注入链路是通的。该文件此前自持一份副本，路径写成三级上溯（解析到仓库外）
// 并静默回落 'dev'，于是那两个用例长期红灯；本文件现改为直接复用共享实现。

// vitest 独立配置（不并入 vite.config.ts，避免把 test 字段混进生产构建配置）。
// 复用与开发一致的 @ 别名，使测试内的 import 路径与源码写法完全一致。
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
  test: {
    // 组件测试需要 DOM 环境。
    environment: 'jsdom',
    // 不开启 globals：测试文件显式 import { describe, it, expect }，类型更清晰、无需额外的 tsconfig types 配置。
    globals: false,
    setupFiles: ['./tests/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}', 'tests/**/*.{test,spec}.{ts,tsx}'],
    // 覆盖率：v8 provider；显式运行 coverage 时需安装同版本 @vitest/coverage-v8。
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/vite-env.d.ts', 'src/main.tsx'],
    },
  },
});
