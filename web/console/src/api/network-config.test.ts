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

it('拒绝权限未知伪装和接管许可，兼容未提供接管报告的旧后端', async () => {
  const base = { id: 'a'.repeat(64), backend: 'netplan', platform: 'linux', scope: 'merged_ethernets', observed_at: '2026-10-28T01:00:00Z', status: 'observed', can_apply: false, sources: [], profiles: [], warnings: [] };
  const respond = (patch: object) => vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { ...base, ...patch } }), { status: 200 })));
  respond({}); await expect(networkConfig.inspectPersistent('netplan')).resolves.toMatchObject({ status: 'observed' });
  for (const patch of [
    { authority: { status: 'review_required', can_adopt: true, issues: [] } },
    { authority: { status: 'review_required', can_adopt: false, issues: [{ source_id: '', reference: '', severity: 'blocker', code: 'x', message: 'blocked' }] } },
    { manager: { state: 'observed', scope: 'all_profiles', observed_at: base.observed_at, diagnostic: '' } },
    { sources: [{ id: 'b'.repeat(64), path: '/etc/netplan/a.yaml', storage: 'persistent', bytes: 10, state: 'read', version_tag: 'c'.repeat(64), safety: { uid: -1, gid: 0, mode: '0600', stable: true, status: 'meets_baseline', codes: [] } }] },
  ]) { respond(patch); await expect(networkConfig.inspectPersistent('netplan')).rejects.toThrow('持久配置来源响应无效'); }
});

it('设备关联必须包含明确的受管状态、状态码和UUID匹配证据', async () => {
  const source = { id: 'b'.repeat(64), path: '/etc/NetworkManager/system-connections/lan.nmconnection', storage: 'persistent', version_tag: 'c'.repeat(64), bytes: 60, state: 'read' };
  const active = { state: 'active', device_state: 100, managed: true, active_profile_matches: true };
  const profile = { reference: 'nm:12345678-1234-1234-1234-123456789abc', device: 'eth0', binding: 'declared', methods: {}, mtu: null, addresses: null, dns: null, search: null, routes: null, field_states: { mtu: 'unset', addresses: 'unset', dns: 'unset', search: 'unset', routes: 'unset' }, source_ids: [source.id], origin_verified: true, device_association: active };
  const evidence = { state: 'observed', scope: 'visible_nm_device_associations', observed_at: '2026-10-29T01:00:00Z', diagnostic: 'contents_and_exclusive_ownership_not_verified' };
  const base = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: evidence.observed_at, status: 'partial', can_apply: false, sources: [source], profiles: [profile], warnings: [], device_evidence: evidence };
  const respond = (patch: object) => vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { ...base, ...patch } }), { status: 200 })));
  for (const association of [active, { state: 'unknown', device_state: 0, managed: null, active_profile_matches: null }, { state: 'unmanaged', device_state: 10, managed: false, active_profile_matches: null }, { state: 'not_observed', device_state: null, managed: null, active_profile_matches: null }, { state: 'conflicting', device_state: 100, managed: true, active_profile_matches: false }]) {
    respond({ profiles: [{ ...profile, device_association: association }] });
    await expect(networkConfig.inspectPersistent('networkmanager')).resolves.toMatchObject({ profiles: [{ device_association: association }] });
  }
  for (const patch of [
    { profiles: [{ ...profile, device_association: { ...active, active_profile_matches: null } }] },
    { profiles: [{ ...profile, device_association: { ...active, managed: false } }] },
    { profiles: [{ ...profile, device_association: { ...active, device_state: 40 } }] },
    { profiles: [{ ...profile, device_association: { ...active, device_state: 101 } }] },
    { profiles: [{ ...profile, device_association: { state: 'unknown', device_state: null, managed: false, active_profile_matches: null } }] },
    { profiles: [{ ...profile, binding: 'unresolved' }] },
    { profiles: [{ ...profile, reference: 'nm:------------------------------------' }] },
    { device_evidence: { ...evidence, state: 'unavailable' } },
    { device_evidence: { ...evidence, scope: 'exclusive_ownership' } },
    { device_evidence: { ...evidence, observed_at: 'invalid' } },
    { platform: 'darwin' },
  ]) {
    respond(patch);
    await expect(networkConfig.inspectPersistent('networkmanager')).rejects.toThrow('持久配置来源响应无效');
  }
});

it('加载比较拒绝伪一致、来源错绑、未知转空与汇总掩盖差异', async () => {
  const source = { id: 'b'.repeat(64), path: '/etc/NetworkManager/system-connections/lan.nmconnection', storage: 'persistent', version_tag: 'c'.repeat(64), bytes: 60, state: 'read' };
  const fields = [
    { field: 'device', state: 'same', reason: 'compared', source: 'eth0', loaded: 'eth0' },
    { field: 'mtu', state: 'different', reason: 'compared', source: 1500, loaded: 0 },
    { field: 'ipv4_method', state: 'same', reason: 'compared', source: 'manual', loaded: 'manual' },
    { field: 'ipv6_method', state: 'unknown', reason: 'source_unset_or_unsupported', source: null, loaded: 'auto' },
    ...['addresses', 'dns', 'search'].map(field => ({ field, state: 'unknown', reason: 'source_unset_or_unsupported', source: null, loaded: [] })),
  ];
  const comparison = { state: 'different', scope: 'nm_profile_scalar_and_sets', observed_at: '2026-10-29T01:00:00Z', diagnostic: 'partial_scope_not_full_sync', fields };
  const profile = { reference: 'nm:12345678-1234-1234-1234-123456789abc', device: 'eth0', binding: 'declared', methods: { ipv4: 'manual', ipv6: 'unspecified' }, mtu: 1500, addresses: null, dns: null, search: null, routes: null, field_states: { mtu: 'configured', addresses: 'unset', dns: 'unset', search: 'unset', routes: 'unset' }, source_ids: [source.id], origin_verified: true, load_reference: 'matched', loaded_comparison: comparison };
  const base = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: comparison.observed_at, status: 'partial', can_apply: false, sources: [source], profiles: [profile], warnings: [] };
  const respond = (patch: object) => vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ data: { ...base, ...patch } }), { status: 200 })));
  respond({}); await expect(networkConfig.inspectPersistent('networkmanager')).resolves.toMatchObject({ profiles: [{ loaded_comparison: { state: 'different' } }] });
  for (const c of [
    { ...comparison, state: 'partial' }, { ...comparison, state: 'passed' }, { ...comparison, fields: [] },
    { ...comparison, fields: fields.map(f => f.field === 'mtu' ? { ...f, state: 'same' } : f) },
    { ...comparison, fields: fields.map(f => f.field === 'device' ? { ...f, source: 'eth1', loaded: 'eth1' } : f) },
    { ...comparison, fields: fields.map(f => f.field === 'dns' ? { ...f, source: [], state: 'same', reason: 'compared' } : f) },
    { ...comparison, fields: fields.map(f => f.field === 'mtu' ? { ...f, loaded: null } : f) },
    { ...comparison, state: 'unavailable' }, { ...comparison, scope: 'full_sync' },
  ]) {
    respond({ profiles: [{ ...profile, loaded_comparison: c }] });
    await expect(networkConfig.inspectPersistent('networkmanager')).rejects.toThrow('持久配置来源响应无效');
  }
  respond({ profiles: [{ ...profile, load_reference: 'conflicting' }] });
  await expect(networkConfig.inspectPersistent('networkmanager')).rejects.toThrow('持久配置来源响应无效');
  respond({ profiles: [{ ...profile, loaded_comparison: { ...comparison, state: 'unavailable', fields: [] } }] });
  await expect(networkConfig.inspectPersistent('networkmanager')).resolves.toMatchObject({ profiles: [{ loaded_comparison: { state: 'unavailable' } }] });
});
