import { defineConfig } from '@umijs/max';
import type { IConfig as WebpackConfig } from '@umijs/bundler-webpack';
import { resolve } from 'node:path';
import { readRootVersion } from '../version-source';
import routes from './routes';

const routerd = process.env.VITE_ROUTERD_TARGET || 'http://127.0.0.1:8080';
export default defineConfig({
  title: 'CythSec 控制台',
  hash: true,
  esbuildMinifyIIFE: true,
  outputPath: process.env.CONSOLE_OUTPUT_PATH || 'dist',
  routes,
  // Preserve v7 package exports (including /dom); Umi's directory alias bypasses them.
  chainWebpack(config: Parameters<NonNullable<WebpackConfig['chainWebpack']>>[0]) { config.resolve.alias.delete('react-router'); },
  layout: { title: 'CythSec', locale: false },
  antd: {
    appConfig: {},
    configProvider: {
      theme: {
        cssVar: true,
      },
    },
  },
  locale: { default: 'zh-CN', antd: true, baseNavigator: false },
  model: {},
  initialState: {},
  request: {},
  mock: false,
  mfsu: false,
  npmClient: 'npm',
  define: {
    __APP_VERSION__: readRootVersion(resolve(__dirname, '..')),
    __ROUTERD_BASE__: process.env.VITE_ROUTERD_BASE || '/api/v1',
    __TELEMETRYD_BASE__: process.env.VITE_TELEMETRYD_BASE || '/telemetry/api/v1',
  },
  proxy: {
    '/telemetry': { target: process.env.VITE_TELEMETRYD_TARGET || 'http://127.0.0.1:8083', changeOrigin: true, pathRewrite: { '^/telemetry': '' } },
    '/api': { target: routerd, changeOrigin: true },
    '/healthz': { target: routerd, changeOrigin: true },
  },
});
