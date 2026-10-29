const target = process.env.CYTHSEC_ROUTERD_TARGET || 'http://127.0.0.1:8080';
const routerd = {
  '/api/v1': { target, changeOrigin: true },
  '/healthz': { target, changeOrigin: true },
};
export default { dev: routerd, test: routerd, pre: routerd };
