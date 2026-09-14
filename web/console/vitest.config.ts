import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { readFileSync } from 'fs';

// 与 vite.config.ts 保持同一条版本注入路径：测试若不注入 __APP_VERSION__，
// 测到的就只是降级值 'dev'，无法验证「版本号来自仓库根 VERSION」这件事本身。
function readRootVersion(): string {
  try {
    return readFileSync(resolve(__dirname, '../../../VERSION'), 'utf-8').trim();
  } catch {
    return 'dev';
  }
}

// vitest 独立配置（不并入 vite.config.ts，避免把 test 字段混进生产构建配置）。
// 复用与开发一致的 @ 别名，使测试内的 import 路径与源码写法完全一致。
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
  test: {
    // 组件测试需要 DOM 环境。
    environment: 'jsdom',
    // 不开启 globals：测试文件显式 import { describe, it, expect }，类型更清晰、无需额外的 tsconfig types 配置。
    globals: false,
    setupFiles: ['./tests/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}', 'tests/**/*.{test,spec}.{ts,tsx}'],
    // 覆盖率：v8 provider，无需额外依赖。
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/vite-env.d.ts', 'src/main.tsx'],
    },
  },
});
