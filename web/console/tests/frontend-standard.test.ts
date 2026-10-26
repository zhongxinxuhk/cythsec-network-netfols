import { expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
it('真实 ESLint 门禁拦截原生替代控件，允许 Ant Design 控件', () => {
  const args = [resolve('node_modules/eslint/bin/eslint.js'), '--stdin', '--stdin-filename', 'src/pages/StandardProbe.tsx', '--parser-options', '{"project":null}'];
  expect(() => execFileSync(process.execPath, args, { input: 'export function Example() { return <button>保存</button>; }', stdio: ['pipe', 'pipe', 'pipe'] })).toThrow();
  expect(execFileSync(process.execPath, args, { input: "import { Button } from 'antd'; export function Example() { return <Button>保存</Button>; }", encoding: 'utf8' })).toBe('');
});
