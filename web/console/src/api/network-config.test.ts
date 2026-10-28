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

it('原生校验绑定目标与文件，拒绝可应用声明和空检查假通过', async () => {
  const response = { draft_digest: 'a'.repeat(64), backend: 'netplan', platform: 'linux', checked_at: '2026-10-27T01:00:00Z', status: 'passed', scope: 'parser', can_apply: false, tool_version: '', checks: [{ artifact: '90-cythsec.yaml', state: 'passed', code: 'parser_accepted', message: '原生解析校验通过' }] };
  const fetch = vi.fn(async () => new Response(JSON.stringify({ data: response }), { status: 200 }));
  vi.stubGlobal('fetch', fetch);
  await expect(networkConfig.validateNative(draft)).resolves.toMatchObject({ status: 'passed', can_apply: false });
  expect((fetch.mock.calls[0] as unknown as [string])[0]).toBe('/api/v1/network/configuration/native-validation');
  for (const patch of [{ can_apply: true }, { checks: [] }, { backend: 'openwrt' }, { checks: [{ ...response.checks[0], state: 'unavailable' }] }, { draft_digest: '' }]) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { ...response, ...patch } }), { status: 200 })));
    await expect(networkConfig.validateNative(draft)).rejects.toThrow('原生配置校验响应无效');
  }
});

it('持久配置只提交backend，并拒绝来源伪造、缺失字段与空值转零', async () => {
  const source = { id: 'b'.repeat(64), path: '/etc/NetworkManager/system-connections/lan.nmconnection', storage: 'persistent', version_tag: 'c'.repeat(64), bytes: 60, state: 'read' };
  const profile = { reference: 'nm:123', device: 'eth0', binding: 'declared', methods: { ipv4: 'manual' }, mtu: null, addresses: ['192.0.2.10/24'], dns: [], search: null, routes: null, field_states: { mtu: 'unset', addresses: 'configured', dns: 'configured', search: 'unset', routes: 'unset' }, source_ids: [source.id], origin_verified: true };
  const report = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: '2026-10-28T01:00:00Z', status: 'partial', can_apply: false, sources: [source], profiles: [profile], warnings: [] };
  const fetch = vi.fn(async () => new Response(JSON.stringify({ data: report }), { status: 200 }));
  vi.stubGlobal('fetch', fetch);
  await expect(networkConfig.inspectPersistent('networkmanager')).resolves.toMatchObject({ status: 'partial' });
  const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
  expect(url).toBe('/api/v1/network/configuration/persistent-inspection');
  expect(JSON.parse(init.body as string)).toEqual({ backend: 'networkmanager' });
  for (const patch of [{ can_apply: true }, { profiles: [{ ...profile, source_ids: ['f'.repeat(64)] }] }, { profiles: [{ ...profile, mtu: 0 }] }, { profiles: [{ ...profile, field_states: {} }] }, { status: 'unavailable' }, { backend: 'netplan' }]) {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { ...report, ...patch } }), { status: 200 })));
    await expect(networkConfig.inspectPersistent('networkmanager')).rejects.toThrow('持久配置来源响应无效');
  }
});
