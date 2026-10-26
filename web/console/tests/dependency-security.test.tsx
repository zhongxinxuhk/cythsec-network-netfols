import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Link, MemoryRouter, useLocation } from 'react-router-dom';

const require = createRequire(resolve('package.json'));

it('the installed Umi entrypoints resolve fixed router APIs including the legacy server subpath', () => {
  for (const name of ['@umijs/renderer-react', '@umijs/server', '@umijs/preset-umi']) {
    const consumer = createRequire(require.resolve(`${name}/package.json`));
    expect(typeof consumer('react-router-dom').Router).toBe('function');
    expect(typeof consumer('react-router-dom/server').StaticRouter).toBe('function');
  }
  expect(require('react-router/package.json').version).toBe('7.18.4');
  // Dva still has a separate v4 API; the security override must not upgrade it.
  const plugins = createRequire(require.resolve('@umijs/plugins/package.json'));
  const dva = createRequire(plugins.resolve('dva/package.json'));
  expect(dva('react-router-dom/package.json').version).toBe('4.3.1');
});

it('normal queries and same-origin backslash links normalize before SPA navigation', () => {
  function CurrentLocation() {
    const location = useLocation();
    return <span data-testid="location">{location.pathname}{location.search}</span>;
  }
  const target = `${String.fromCharCode(92).repeat(2)}${window.location.host}\\analytics?from=1`;
  render(<MemoryRouter initialEntries={['/']}>
    <Link to={target}>查询</Link><CurrentLocation />
  </MemoryRouter>);
  try {
    fireEvent.click(screen.getByText('查询'));
    expect(screen.getByTestId('location')).toHaveTextContent('/analytics?from=1');
  } finally { cleanup(); }
});

it('the fixed decoder remains compatible with query-string and bounds malformed-input processing', () => {
  const history = createRequire(require.resolve('@umijs/history/package.json'));
  const query = history('query-string');
  expect(query.parse('q=a+b&x=%E4%B8%AD&x=2')).toEqual({ q: 'a b', x: ['中', '2'] });
  const result = execFileSync(process.execPath, ['-e', `
    const decode = require('decode-uri-component');
    const value = decode('%E0%A4%A'.repeat(10000));
    if (typeof value !== 'string') process.exit(1);
    console.log('completed');
  `], { timeout: 3000, encoding: 'utf8' });
  expect(result.trim()).toBe('completed');
});

it('removes the vulnerable crypto chain and rejects unsupported Node crypto rather than returning a stub', () => {
  const lock = JSON.parse(readFileSync(resolve('package-lock.json'), 'utf8'));
  const paths = Object.keys(lock.packages);
  expect(paths.filter((path) => /node_modules\/(elliptic|crypto-browserify|browserify-sign|create-ecdh)$/.test(path))).toEqual([]);
  for (const name of ['node-libs-browser', 'node-libs-browser-okam']) {
    const builtins = require(name);
    expect(typeof builtins.buffer).toBe('string');
    expect(() => require(builtins.crypto)).toThrow('does not support Node crypto polyfills');
  }
});
