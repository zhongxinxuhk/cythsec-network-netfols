import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
it('开发服务器未指定 host 时仍只监听 loopback', () => {
  const output = execFileSync(
    process.execPath,
    [
      '--require',
      resolve(__dirname, '../scripts/dev-loopback.cjs'),
      '-e',
      "const s=require('node:http').createServer();s.listen(0,()=>{console.log(s.address().address);s.close()})",
    ],
    { env: { ...process.env, PORT: '0' }, encoding: 'utf8' },
  );
  expect(output.trim()).toBe('127.0.0.1');
});
