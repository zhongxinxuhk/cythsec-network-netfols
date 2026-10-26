import { expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
it('真实 ESLint 门禁拦截原生替代控件，允许 Ant Design 控件', () => {
  const args = [resolve('node_modules/eslint/bin/eslint.js'), '--stdin', '--stdin-filename', 'src/pages/StandardProbe.tsx', '--parser-options', '{"project":null}'];
  expect(() => execFileSync(process.execPath, args, { input: 'export function Example() { return <button>保存</button>; }', stdio: ['pipe', 'pipe', 'pipe'] })).toThrow();
  expect(execFileSync(process.execPath, args, { input: "import { Button } from 'antd'; export function Example() { return <Button>保存</Button>; }", encoding: 'utf8' })).toBe('');
});
it('开发服务器真实 socket 只绑定回环 IP，并拒绝显式通配监听', () => {
  const guard = resolve('scripts/loopback-only.cjs');
  const code = "const server = require('node:http').createServer(); server.listen(0, () => { console.log(server.address().address); server.close(); });";
  expect(execFileSync(process.execPath, ['--require', guard, '-e', code], { encoding: 'utf8' }).trim()).toBe('127.0.0.1');
  expect(() => execFileSync(process.execPath, ['--require', guard, '-e', "require('node:http').createServer().listen(0, '0.0.0.0');"], { stdio: 'pipe' })).toThrow();
});
