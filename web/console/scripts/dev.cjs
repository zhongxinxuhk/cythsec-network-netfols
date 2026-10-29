const { spawn } = require('node:child_process');
const { join } = require('node:path');
const env = {
  ...process.env,
  HOST: '127.0.0.1',
  PORT: '15173',
  UMI_ENV: process.env.UMI_ENV || 'dev',
};
if (env.MOCK !== 'none')
  env.ANT_DESIGN_PRO_ONLY_DO_NOT_USE_IN_YOUR_PRODUCTION = 'site';
env.NODE_OPTIONS = [
  env.NODE_OPTIONS,
  `--require=${JSON.stringify(join(__dirname, 'dev-loopback.cjs'))}`,
]
  .filter(Boolean)
  .join(' ');
const child = spawn(
  process.execPath,
  [require.resolve('@umijs/max/bin/max.js'), 'dev', ...process.argv.slice(2)],
  { env, stdio: 'inherit' },
);
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => child.kill(signal));
child.on('error', (error) => {
  console.error(error);
  process.exitCode = 1;
});
child.on('exit', (code) => {
  process.exitCode = code ?? 1;
});
