import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { HeaderStatus } from './HeaderStatus';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('两个服务独立判断，遥测离线不能被控制面正常掩盖', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => Promise.resolve({ ok: url === '/healthz', status: 503 })));
  render(<HeaderStatus />);
  expect(await screen.findByText('routerd online')).toBeInTheDocument();
  expect(await screen.findByText('telemetryd offline')).toBeInTheDocument();
});
