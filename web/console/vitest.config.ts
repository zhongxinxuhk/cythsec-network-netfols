import { defineConfig } from 'vitest/config';
import { resolve } from 'path';
import { readRootVersion } from './version-source';

// 组件测试独立于 Umi 构建，复用同一版本真源与 API 编译期常量。
export default defineConfig({
  esbuild: { jsx: 'automatic' },
  define: {
    __APP_VERSION__: JSON.stringify(readRootVersion(__dirname)),
    __ROUTERD_BASE__: JSON.stringify('/api/v1'),
    __TELEMETRYD_BASE__: JSON.stringify('/telemetry/api/v1'),
  },
  resolve: {
    alias: [
      { find: '@', replacement: resolve(__dirname, 'src') },
      // 与浏览器构建相同的 ESM 入口，规避 Node 条件入口只导出 default。
      { find: /^@ant-design\/pro-components$/, replacement: resolve(__dirname, 'node_modules/@ant-design/pro-components/es/index.js') },
      { find: /^@ant-design\/icons$/, replacement: resolve(__dirname, 'node_modules/@ant-design/icons/es/index.js') },
    ],
  },
  test: {
    // 组件测试需要 DOM 环境。
    environment: 'jsdom',
    // 不开启 globals：测试文件显式 import { describe, it, expect }，类型更清晰、无需额外的 tsconfig types 配置。
    globals: false,
    deps: { optimizer: { client: { enabled: true, include: ['@ant-design/pro-components', 'antd', '@ant-design/icons'] } } },
    setupFiles: ['./tests/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}', 'tests/**/*.{test,spec}.{ts,tsx}'],
    // 覆盖率：v8 provider；显式运行 coverage 时需安装同版本 @vitest/coverage-v8。
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/globals.d.ts', 'src/app.tsx'],
    },
  },
});
