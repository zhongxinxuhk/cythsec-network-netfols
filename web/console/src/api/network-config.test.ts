import { afterEach, expect, it, vi } from 'vitest';
import { networkConfig, type NetworkDraft } from './network-config';
const draft: NetworkDraft = { backend: 'netplan', interfaces: [] };
afterEach(() => vi.unstubAllGlobals());
it('预览与版本写入使用同源routerd路径，写入提交精确If-Match', async () => {
  const fetch = vi.fn(async () => new Response(JSON.stringify({ data: { revision: 2, stage: 'draft_saved', updated_at: null, config: draft } }), { status: 200 }));
  vi.stubGlobal('fetch', fetch);
  await networkConfig.save(draft, 1);
  const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
  expect(url).toBe('/api/v1/network/configuration');
  expect(init.method).toBe('PUT');
  expect(new Headers(init.headers).get('If-Match')).toBe('"1"');
  expect(init.body).toBe(JSON.stringify(draft));
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: '配置版本已变化' }), { status: 412 })));
  await expect(networkConfig.save(draft, 1)).rejects.toMatchObject({ status: 412 });
});
