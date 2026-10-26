import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { accessRevision, connect, disconnect, secureFetch, serviceAccess } from './http';
const credential = 'temporary-test-access-'.repeat(3);
const identity = { enabled: true, name: 'qa-reader', role: 'viewer', can_ingest: false };
const response = (data: unknown, status = 200) => ({ ok: status < 300, status, json: async () => ({ data }) }) as Response;
beforeEach(() => { disconnect('routerd'); disconnect('telemetryd'); });
afterEach(() => { disconnect('routerd'); disconnect('telemetryd'); vi.unstubAllGlobals(); });
it('only the selected service receives the validated credential, without persistence or redirects', async () => {
  const fetcher = vi.fn().mockResolvedValue(response(identity)); vi.stubGlobal('fetch', fetcher);
  await connect('routerd', credential);
  await secureFetch('routerd', '/system'); await secureFetch('telemetryd', '/analytics/imports');
  const first = fetcher.mock.calls[1][1] as RequestInit, second = fetcher.mock.calls[2][1] as RequestInit;
  expect(new Headers(first.headers).get('Authorization')).toBe(`Bearer ${credential}`);
  expect(new Headers(second.headers).has('Authorization')).toBe(false);
  expect(first).toMatchObject({ redirect: 'error', cache: 'no-store' });
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0);
});
it('invalid or disabled authentication cannot establish a connected identity', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ enabled: false, can_ingest: false })));
  const before = accessRevision(); await expect(connect('routerd', credential)).rejects.toThrow('未启用鉴权');
  expect(accessRevision()).toBe(before);
  vi.mocked(fetch).mockResolvedValue(response(identity, 401));
  await expect(connect('routerd', credential)).rejects.toThrow('需要服务访问凭据');
  expect(accessRevision()).toBe(before);
});
it('disconnect discards late responses and expired credentials are removed on 401', async () => {
  const fetcher = vi.fn().mockResolvedValue(response(identity)); vi.stubGlobal('fetch', fetcher);
  await connect('routerd', credential);
  let complete!: (response: Response) => void;
  fetcher.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
  const pending = secureFetch('routerd', '/system'); disconnect('routerd'); complete(response({ hostname: 'old-identity' }));
  await expect(pending).rejects.toThrow('访问身份已变化');
  fetcher.mockResolvedValue(response(identity)); await connect('routerd', credential);
  fetcher.mockResolvedValueOnce(response(null, 401)); await serviceAccess('routerd').catch(() => {});
  await secureFetch('routerd', '/system');
  expect(new Headers(fetcher.mock.calls[fetcher.mock.calls.length - 1][1].headers).has('Authorization')).toBe(false);
});
it('an old 401 cannot erase a newer validated credential', async () => {
  const fetcher = vi.fn().mockResolvedValue(response(identity)); vi.stubGlobal('fetch', fetcher);
  await connect('routerd', credential);
  let complete!: (response: Response) => void;
  fetcher.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
  const old = secureFetch('routerd', '/system');
  const replacement = `${credential}-new`;
  await connect('routerd', replacement); complete(response(null, 401));
  await expect(old).rejects.toThrow('访问身份已变化');
  await secureFetch('routerd', '/system');
  expect(new Headers(fetcher.mock.calls[fetcher.mock.calls.length - 1][1].headers).get('Authorization')).toBe(`Bearer ${replacement}`);
});
it('从匿名开放模式切换为要求认证时清空旧页面，重复401不会重挂载循环', async () => {
  const fetcher = vi.fn().mockResolvedValue(response({ enabled: false, can_ingest: false })); vi.stubGlobal('fetch', fetcher);
  await serviceAccess('routerd');
  const before = accessRevision(); fetcher.mockResolvedValue(response(null, 401));
  await secureFetch('routerd', '/system');
  expect(accessRevision()).toBe(before + 1);
  await secureFetch('routerd', '/system');
  expect(accessRevision()).toBe(before + 1);
});

it('a delayed anonymous session body cannot clear a newly connected credential', async () => {
  let complete!: (value: unknown) => void;
  let parsing!: () => void;
  const started = new Promise<void>((resolve) => { parsing = resolve; });
  const body = new Promise((resolve) => { complete = resolve; });
  const fetcher = vi.fn().mockResolvedValueOnce({ ok: true, status: 200, json: () => { parsing(); return body; } }).mockResolvedValue(response(identity));
  vi.stubGlobal('fetch', fetcher);
  const old = serviceAccess('routerd');
  await started;
  await connect('routerd', credential);
  complete({ data: { enabled: false, can_ingest: false } });
  await expect(old).rejects.toThrow('访问身份已变化');
  await secureFetch('routerd', '/system');
  expect(new Headers(fetcher.mock.calls[fetcher.mock.calls.length - 1][1].headers).get('Authorization')).toBe(`Bearer ${credential}`);
});
