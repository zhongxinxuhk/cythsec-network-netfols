import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
import { readRootVersion } from './version-source';
export default defineConfig({
  define: { __APP_VERSION__: JSON.stringify(readRootVersion(__dirname)) },
  resolve: { alias: { '@': resolve(__dirname, 'src') } },
  test: {
    environment: 'node',
    include: [
      'src/utils/*.test.ts',
      'tests/api-client.test.ts',
      'tests/dev-loopback.test.ts',
      'tests/dependency-security.test.ts',
      'src/navigation/catalog.test.ts',
    ],
  },
});
