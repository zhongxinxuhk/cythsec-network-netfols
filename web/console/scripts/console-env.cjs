// One browser entry for npm, CLion and built-output preview. Umi owns the server.
const args = process.argv.slice(2);
const portIndex = args.indexOf('--port');
const argumentPort = portIndex >= 0 ? args[portIndex + 1] : args.find(value => value.startsWith('--port='))?.slice(7);
const port = process.env.PORT || argumentPort || '15173';
if (!/^\d+$/.test(port) || Number(port) < 1024 || Number(port) > 65535) {
  throw new Error('Console PORT must be an integer between 1024 and 65535');
}
if (argumentPort && argumentPort !== port) throw new Error('Console PORT and --port must match');
process.env.PORT = port;
process.env.STRICT_PORT = port;
process.env.CYTHSEC_CONSOLE_PORT = port;
process.env.HOST = '127.0.0.1';
process.env.VITE_ROUTERD_TARGET ||= 'http://127.0.0.1:18080';
process.env.VITE_TELEMETRYD_TARGET ||= 'http://127.0.0.1:18083';
if (args[0] === 'preview' && !argumentPort) process.argv.push('--port', port);
