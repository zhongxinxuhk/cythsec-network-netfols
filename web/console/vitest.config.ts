import { join } from 'node:path';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    {
      name: 'vitest-md-raw-loader',
      transform(code, id) {
        if (!id.endsWith('.md')) {
          return null;
        }
        return {
          code: `export default ${JSON.stringify(String(code))};`,
          map: null,
        };
      },
    },
  ],
  resolve: {
    alias: [
      { find: '@', replacement: join(__dirname, 'src') },
      { find: '@root', replacement: join(__dirname) },
      { find: '@@', replacement: join(__dirname, 'src', '.umi') },
      // 浏览器测试使用 Umi 生成的客户端出口，避免导入 npm 根入口的 Node CLI / fsevents。
      {
        find: /^@umijs\/max$/,
        replacement: join(__dirname, 'src', '.umi', 'exports.ts'),
      },
      {
        find: /^umi$/,
        replacement: join(__dirname, 'src', '.umi', 'exports.ts'),
      },
    ],
  },
  test: {
    browser: {
      enabled: true,
      viewport: { width: 1280, height: 900 },
      provider: playwright(),
      headless: true,
      instances: [{ browser: 'chromium' }],
    },
    globals: true,
    setupFiles: ['./tests/setupTests.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: [
      'node_modules',
      'dist',
      '.umi',
      'src/utils/*.test.ts',
      'src/navigation/catalog.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/.umi/**',
        'src/.umi-test/**',
        'src/.umi-production/**',
        'src/services/ant-design-pro/**',
        'src/**/*.d.ts',
        'src/**/index.style.ts',
      ],
    },
    passWithNoTests: false,
    testTimeout: 15000,
  },
});
