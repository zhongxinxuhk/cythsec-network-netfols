import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { disconnect } from '@/api/http';
import { AccessBoundary, ServiceAccess } from './ServiceAccess';
const credential = 'local-ui-test-access-'.repeat(3);
afterEach(() => { cleanup(); disconnect('routerd'); disconnect('telemetryd'); vi.unstubAllGlobals(); });
it('真实连接校验成功才展示身份，断开后移除身份和凭据', async () => {
  const fetcher = vi.fn((_url: string, init?: RequestInit) => {
    const accepted = new Headers(init?.headers).get('Authorization') === `Bearer ${credential}`;
    return Promise.resolve({ ok: accepted, status: accepted ? 200 : 401, json: async () => ({ data: { enabled: true, name: 'qa-reader', role: 'viewer', can_ingest: false } }) });
  });
  vi.stubGlobal('fetch', fetcher);
  render(<AccessBoundary><ServiceAccess /></AccessBoundary>);
  fireEvent.click(screen.getByRole('button', { name: /访问认证/ }));
  fireEvent.click(await screen.findByRole('button', { name: /控制面 · 连接认证/ }));
  fireEvent.change(screen.getByLabelText('访问凭据'), { target: { value: credential } });
  fireEvent.click(screen.getByRole('button', { name: /^连接服务$/ }));
  await waitFor(() => expect(screen.queryByLabelText('访问凭据')).not.toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: /访问认证/ }));
  expect(await screen.findByText(/控制面.*qa-reader.*只读/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /断开控制面/ }));
  await waitFor(() => expect(screen.queryByText(/qa-reader/)).not.toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: /访问认证/ }));
  expect(await screen.findByRole('button', { name: /控制面 · 连接认证/ })).toBeInTheDocument();
});
