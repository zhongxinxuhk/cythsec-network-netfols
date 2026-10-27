import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { expect, it } from 'vitest';

const environment = resolve('scripts/console-env.cjs');
const guard = resolve('scripts/loopback-only.cjs');
const env = { ...process.env, PORT: '', CYTHSEC_CONSOLE_PORT: '', STRICT_PORT: '' };

it('npm开发和预览共用15173及同源后端代理目标', () => {
  const output = execFileSync(process.execPath, ['--require', environment, '-e', 'console.log(JSON.stringify([process.env.PORT,process.env.STRICT_PORT,process.env.HOST]))'], { encoding: 'utf8', env });
  expect(JSON.parse(output)).toEqual(['15173', '15173', '127.0.0.1']);
});

it('端口非法或被Umi改为其他端口时失败，不启动第二个HTTP入口', () => {
  expect(() => execFileSync(process.execPath, ['--require', environment, '-e', ''], { env: { ...env, PORT: '90000' }, stdio: 'pipe' })).toThrow();
  expect(() => execFileSync(process.execPath, ['--require', environment, '--require', guard, '-e', "require('node:http').createServer().listen(15174)"], { env, stdio: 'pipe' })).toThrow(/refusing fallback/);
});

it('端口冲突在加载Umi前失败，保护已运行控制台的生成目录', async () => {
  const server = createServer();
  await new Promise<void>(ready => server.listen(0, '127.0.0.1', ready));
  const port = (server.address() as AddressInfo).port;
  try {
    expect(() => execFileSync(process.execPath, [resolve('scripts/start-console.cjs'), 'dev'], {
      env: { ...env, PORT: String(port) }, timeout: 5000, stdio: 'pipe',
    })).toThrow(/existing instance left running/);
  } finally {
    await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done()));
  }
});
