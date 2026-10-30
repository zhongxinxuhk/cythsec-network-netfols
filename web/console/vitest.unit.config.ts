import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
import { readRootVersion } from './version-source';
export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(readRootVersion(__dirname)), __ROUTERD_BASE__: JSON.stringify('/api/v1'), __TELEMETRYD_BASE__: JSON.stringify('/telemetry/api/v1') },
  resolve: { alias: { '@': resolve(__dirname, 'src') } },
  test: {
    environment: 'node',
    include: ['src/utils/*.test.ts', 'tests/*.test.ts', 'src/navigation/catalog.test.ts'],
  },
});
