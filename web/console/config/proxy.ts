const target = process.env.CYTHSEC_ROUTERD_TARGET || process.env.VITE_ROUTERD_TARGET || 'http://127.0.0.1:8080';
const routerd = {
  '/telemetry': { target: process.env.CYTHSEC_TELEMETRYD_TARGET || process.env.VITE_TELEMETRYD_TARGET || 'http://127.0.0.1:8083', changeOrigin: true, pathRewrite: { '^/telemetry': '' } },
  '/api/v1': { target, changeOrigin: true },
  '/healthz': { target, changeOrigin: true },
};
export default { dev: routerd, test: routerd, pre: routerd };
