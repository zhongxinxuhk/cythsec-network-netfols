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
it('拒绝错误环境结构与未支持的可应用声明', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: {} }), { status: 200 })));
  await expect(networkConfig.observe()).rejects.toThrow('网络环境响应无效');
  const observation = { id: 'a'.repeat(64), platform: 'linux', observed_at: '2026-10-27T01:00:00Z', status: 'partial', inventory_available: true, interfaces: [], managers: [] };
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { observation, status: 'review_required', can_apply: true, issues: [], differences: [] } }), { status: 200 })));
  await expect(networkConfig.preflight(draft)).rejects.toThrow('应用前检查响应无效');
});
