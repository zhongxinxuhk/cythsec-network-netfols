import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import type { PersistentNetworkInspection } from '@/api/network-config';
import { PersistentNetworkResult } from './PersistentNetworkResult';
afterEach(cleanup);
it('来源投影区分未配置、空集合与默认Metric，保留持久和临时文件证据', async () => {
  const source = { id: 'a'.repeat(64), path: '/etc/config/network', storage: 'persistent' as const, state: 'read' as const, bytes: 120, version_tag: 'b'.repeat(64) };
  const report: PersistentNetworkInspection = {
    id: 'c'.repeat(64), backend: 'openwrt', platform: 'linux', scope: 'committed_network', observed_at: '2026-10-28T01:00:00Z', status: 'partial', can_apply: false,
    sources: [source, { ...source, id: 'd'.repeat(64), path: '/run/source', storage: 'runtime', state: 'unavailable', bytes: 0, version_tag: '' }],
    profiles: [{ reference: 'uci:lan', device: 'eth0', binding: 'declared', methods: { protocol: 'static' }, mtu: null, addresses: ['192.0.2.10/24'], dns: [], search: null,
      routes: [{ destination: '0.0.0.0/0', gateway: '192.0.2.1', metric: null }], field_states: { mtu: 'unset', addresses: 'configured', dns: 'configured', search: 'unsupported', routes: 'configured' }, source_ids: [source.id], origin_verified: true }], warnings: ['source_read_incomplete'],
  };
  await act(async () => { render(<PersistentNetworkResult report={report} />); });
  expect(screen.getByText('显式空集合')).toBeInTheDocument();
  expect(screen.getByText('未显式配置')).toBeInTheDocument();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: /展开行|Expand row/i })); });
  expect(screen.getByText('未解析')).toBeInTheDocument();
  expect(screen.getByText('静态路由声明')).toBeInTheDocument();
  expect(screen.getAllByText('未显式配置')).toHaveLength(2);
  await act(async () => { fireEvent.click(screen.getByRole('tab', { name: '来源证据' })); });
  expect(screen.getByText('持久文件')).toBeInTheDocument();
  expect(screen.getByText('临时文件')).toBeInTheDocument();
  expect(screen.getByText('不可读取')).toBeInTheDocument();
  const missing = screen.getByText('/run/source').closest('tr');
  expect(missing).toHaveTextContent('未取得');
  expect(screen.queryByText('0 B')).not.toBeInTheDocument();
});

it('引用匹配不冒充内容同步，接管检查始终不可执行', async () => {
  const report: PersistentNetworkInspection = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: '2026-10-28T01:00:00Z', status: 'partial', can_apply: false, sources: [], profiles: [], warnings: [],
    manager: { state: 'observed', scope: 'visible_profile_references', observed_at: '2026-10-28T01:00:00Z', diagnostic: 'contents_and_activation_not_verified' },
    authority: { status: 'blocked', can_adopt: false, issues: [{ source_id: '', reference: '', severity: 'blocker', code: 'source_inventory_incomplete', message: '来源清单尚未完整核验' }] } };
  await act(async () => { render(<PersistentNetworkResult report={report} />); });
  await act(async () => { fireEvent.click(screen.getByRole('tab', { name: '接管条件' })); });
  const panel = screen.getByRole('tabpanel', { name: '接管条件' });
  expect(within(panel).getByText('存在接管阻断项')).toBeInTheDocument();
  expect(within(panel).getByText('已取得可见引用')).toBeInTheDocument();
  expect(within(panel).getByText('完整内容同步')).toBeInTheDocument();
  expect(within(panel).getByText('待核验')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '确认接管' })).not.toBeInTheDocument();
});

it('设备关联区分激活、配置冲突、未知与未受管，旧后端不回填否', async () => {
  const source = { id: 'b'.repeat(64), path: '/etc/NetworkManager/system-connections/lan.nmconnection', storage: 'persistent' as const, version_tag: 'c'.repeat(64), bytes: 60, state: 'read' as const };
  const profile: PersistentNetworkInspection['profiles'][number] = { reference: 'nm:12345678-1234-1234-1234-123456789abc', device: 'eth0', binding: 'declared', methods: {}, mtu: null, addresses: null, dns: null, search: null, routes: null, field_states: { mtu: 'unset', addresses: 'unset', dns: 'unset', search: 'unset', routes: 'unset' }, source_ids: [source.id], origin_verified: true };
  const report: PersistentNetworkInspection = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: '2026-10-29T01:00:00Z', status: 'partial', can_apply: false, sources: [source], warnings: [], profiles: [
    { ...profile, device_association: { state: 'active', device_state: 100, managed: true, active_profile_matches: true } },
    { ...profile, reference: 'nm:other', device_association: { state: 'conflicting', device_state: 100, managed: true, active_profile_matches: false } },
    { ...profile, reference: 'nm:unmanaged', device_association: { state: 'unmanaged', device_state: 10, managed: false, active_profile_matches: null } },
    { ...profile, reference: 'nm:old' },
  ], device_evidence: { state: 'observed', scope: 'visible_nm_device_associations', observed_at: '2026-10-29T01:00:00Z', diagnostic: '' } };
  await act(async () => { render(<PersistentNetworkResult report={report} />); });
  await act(async () => { fireEvent.click(screen.getByRole('tab', { name: '设备关联' })); });
  const panel = screen.getByRole('tabpanel', { name: '设备关联' });
  expect(within(panel).getByText('当前配置已激活')).toBeInTheDocument();
  expect(within(panel).getByText('设备正在使用其他配置')).toBeInTheDocument();
  expect(within(panel).getByText('NM 未管理')).toBeInTheDocument();
  const old = within(panel).getByText('nm:old').closest('tr');
  expect(old).not.toHaveTextContent('否');
  expect(old).not.toHaveTextContent('未激活');
  expect(within(old as HTMLElement).getAllByText('未知')).toHaveLength(4);
  expect(screen.queryByRole('button', { name: /应用|接管/ })).not.toBeInTheDocument();
});

it('加载差异展示自动MTU、不同与来源未配置，不将空集合充当未知', async () => {
  const report: PersistentNetworkInspection = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: '2026-10-29T01:00:00Z', status: 'partial', can_apply: false, sources: [], warnings: [], profiles: [
    { reference: 'nm:12345678-1234-1234-1234-123456789abc', device: 'eth0', binding: 'declared', methods: {}, mtu: 1500, addresses: null, dns: null, search: null, routes: null, field_states: { mtu: 'configured', addresses: 'unset', dns: 'unset', search: 'unset', routes: 'unset' }, source_ids: ['b'.repeat(64)], origin_verified: true,
      loaded_comparison: { state: 'different', scope: 'nm_profile_scalar_and_sets', observed_at: '2026-10-29T01:00:00Z', diagnostic: 'partial_scope_not_full_sync', fields: [
        { field: 'mtu', state: 'different', reason: 'compared', source: 1500, loaded: 0 },
        { field: 'dns', state: 'unknown', reason: 'source_unset_or_unsupported', source: null, loaded: [] },
      ] } },
  ] };
  await act(async () => { render(<PersistentNetworkResult report={report} />); });
  await act(async () => { fireEvent.click(screen.getByRole('tab', { name: '加载差异' })); });
  const panel = screen.getByRole('tabpanel', { name: '加载差异' });
  expect(within(panel).getByText('存在加载差异')).toBeInTheDocument();
  await act(async () => { fireEvent.click(within(panel).getByRole('button', { name: /展开行|Expand row/i })); });
  expect(within(panel).getByText('自动')).toBeInTheDocument();
  expect(within(panel).getByText('不同')).toBeInTheDocument();
  expect(within(panel).getByText('空集合')).toBeInTheDocument();
  expect(within(panel).getByText('来源未显式配置或格式未解析')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '应用配置' })).not.toBeInTheDocument();
});

it('路由差异保留重复声明，未核验加载值不显示为空集合', async () => {
  const tuple = '198.51.100.0/24 via 192.0.2.1 metric default';
  const report: PersistentNetworkInspection = { id: 'a'.repeat(64), backend: 'networkmanager', platform: 'linux', scope: 'keyfile_profiles', observed_at: '2026-10-29T01:00:00Z', status: 'partial', can_apply: false, sources: [], warnings: [], profiles: [
    { reference: 'nm:12345678-1234-1234-1234-123456789abc', device: 'eth0', binding: 'declared', methods: {}, mtu: null, addresses: null, dns: null, search: null, routes: [{ destination: '198.51.100.0/24', gateway: '192.0.2.1', metric: null }, { destination: '198.51.100.0/24', gateway: '192.0.2.1', metric: null }], field_states: { mtu: 'unset', addresses: 'unset', dns: 'unset', search: 'unset', routes: 'configured' }, source_ids: ['b'.repeat(64)], origin_verified: true,
      routing_comparison: { state: 'unknown', scope: 'nm_declared_route_multiset', observed_at: '2026-10-29T01:00:00Z', reason: 'loaded_route_semantics_unsupported', source: [tuple, tuple], loaded: null } },
  ] };
  await act(async () => { render(<PersistentNetworkResult report={report} />); });
  await act(async () => { fireEvent.click(screen.getByRole('tab', { name: '路由差异' })); });
  const panel = screen.getByRole('tabpanel', { name: '路由差异' });
  expect(within(panel).getByText('路由语义未核验')).toBeInTheDocument();
  await act(async () => { fireEvent.click(within(panel).getByRole('button', { name: /展开行|Expand row/i })); });
  expect(within(panel).getAllByText(tuple)).toHaveLength(2);
  expect(within(panel).getByText('未核验')).toBeInTheDocument();
  expect(within(panel).queryByText('显式空路由集合')).not.toBeInTheDocument();
});
