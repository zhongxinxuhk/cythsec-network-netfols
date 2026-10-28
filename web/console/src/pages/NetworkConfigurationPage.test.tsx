import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ApiError } from '@/api/http';
import { networkConfig, type NetworkState, type NetworkObservation, type NetworkPreflight } from '@/api/network-config';
vi.mock('@/api/network-config', () => ({ networkConfig: { read: vi.fn(), preview: vi.fn(), save: vi.fn(), observe: vi.fn(), preflight: vi.fn() } }));
vi.mock('@/api/client', () => ({ api: { interfaces: vi.fn(async () => []) } }));
import NetworkConfigurationPage from './NetworkConfigurationPage';
const state: NetworkState = { snapshot: { revision: 3, updated_at: null, stage: 'draft_saved', config: { backend: 'netplan', interfaces: [{ id: 'lan', device: 'eth0', mtu: 1500, addresses: ['192.0.2.10/24'], dns: ['192.0.2.53'], search: [], routes: [] }] } }, capabilities: { platform: 'linux', can_preview: true, can_observe: true, can_preflight: true, can_save: false, can_apply: false, store_enabled: true, preview_backends: ['netplan', 'networkmanager', 'openwrt'] } };
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it('预览使用真实表单值，只读身份不能保存，也不显示未实现的应用动作', async () => {
  vi.mocked(networkConfig.read).mockResolvedValue(state);
  vi.mocked(networkConfig.preview).mockResolvedValue({ digest: 'a'.repeat(64), stage: 'validated_preview', artifacts: [{ name: '90-cythsec.yaml', content: '{"network":{}}' }] });
  render(<NetworkConfigurationPage />);
  await screen.findByDisplayValue('eth0');
  expect(screen.getByRole('button', { name: '保存草稿' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: '校验并预览' }));
  await screen.findByRole('dialog', { name: '原生配置预览' });
  expect(networkConfig.preview).toHaveBeenCalledWith(state.snapshot.config);
  expect(screen.getByText('校验已完成，配置尚未应用')).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: '90-cythsec.yaml' })).toHaveAttribute('readonly');
  expect(networkConfig.save).not.toHaveBeenCalled();
  expect(screen.queryByRole('button', { name: '应用配置' })).not.toBeInTheDocument();
}, 15000);
it('管理员保存版本与冲突分别反馈，冲突保留编辑内容并阻止覆盖', async () => {
  vi.mocked(networkConfig.read).mockResolvedValue({ ...state, capabilities: { ...state.capabilities, can_save: true } });
  vi.mocked(networkConfig.save).mockResolvedValueOnce({ ...state.snapshot, revision: 4 }).mockRejectedValue(new ApiError('conflict', 412));
  render(<NetworkConfigurationPage />);
  await screen.findByDisplayValue('eth0');
  fireEvent.click(screen.getByRole('button', { name: '保存草稿' }));
  await screen.findByText('草稿已保存 · 版本 4');
  expect(networkConfig.save).toHaveBeenCalledWith(state.snapshot.config, 3);
  fireEvent.click(screen.getByRole('button', { name: '保存草稿' }));
  await screen.findByText(/服务端配置版本已变化，当前编辑已保留/);
  expect(screen.getByDisplayValue('eth0')).toBeInTheDocument();
  await waitFor(() => expect(screen.getByRole('button', { name: '保存草稿' })).toBeDisabled());
}, 15000);

const observed: NetworkObservation = {
  id: 'b'.repeat(64), platform: 'linux', started_at: '2026-10-27T01:00:00Z', observed_at: '2026-10-27T01:00:01Z', inventory_available: true, status: 'partial',
  managers: [{ backend: 'networkd', state: 'active', tool_version: '255', diagnostic: '' }],
  interfaces: [{ device: 'eth0', kind: 'physical_ethernet', up: true, mtu: 1500, addresses: ['192.0.2.10/24'], dns: null, search: null, routes: [], owners: [{ backend: 'networkd', reference: '10-netplan-eth0.network', source: 'networkd_dbus' }], known: { mtu: true, addresses: true, dns: false, routes: true }, sources: { mtu: 'kernel' } }], warnings: ['persistent_configuration_not_read'],
};
it('应用前检查绑定当前草稿，未知DNS不变为空集合或可应用结论', async () => {
  const report: NetworkPreflight = { draft_digest: 'a'.repeat(64), observation: observed, status: 'review_required', can_apply: false, issues: [{ severity: 'review', device: '', code: 'native_validation_pending', message: '原生配置校验与事务应用尚未发布' }], differences: [{ device: 'eth0', field: 'dns', current: null, desired: ['192.0.2.53'], state: 'unknown', source: 'unavailable' }] };
  vi.mocked(networkConfig.read).mockResolvedValue({ ...state, capabilities: { ...state.capabilities, can_preflight: true } });
  vi.mocked(networkConfig.preflight).mockResolvedValue(report);
  render(<NetworkConfigurationPage />);
  await screen.findByDisplayValue('eth0');
  fireEvent.click(screen.getByRole('button', { name: '应用前检查' }));
  const dialog = await screen.findByRole('dialog', { name: '应用前检查' });
  expect(networkConfig.preflight).toHaveBeenCalledWith(state.snapshot.config);
  fireEvent.click(within(dialog).getByRole('tab', { name: '运行态差异' }));
  const row = within(dialog).getByRole('row', { name: /链路DNS/ });
  expect(row).toHaveTextContent('未取得'); expect(row).toHaveTextContent('未知'); expect(row).not.toHaveTextContent('空集合');
  expect(screen.queryByRole('button', { name: '应用配置' })).not.toBeInTheDocument();
}, 15000);
it('环境刷新失败清除旧接口快照，不显示零接口成功', async () => {
  vi.mocked(networkConfig.read).mockResolvedValue(state);
  vi.mocked(networkConfig.observe).mockResolvedValueOnce(observed).mockRejectedValue(new Error('读取超时'));
  render(<NetworkConfigurationPage />);
  await screen.findByDisplayValue('eth0');
  fireEvent.click(screen.getByText('网络环境与接口归属', { exact: true }));
  fireEvent.click(screen.getByRole('button', { name: '读取环境' }));
  await screen.findByText('接口快照 · 1 项');
  fireEvent.click(screen.getByRole('button', { name: '读取环境' }));
  await screen.findByText('读取超时');
  expect(screen.queryByText('接口快照 · 1 项')).not.toBeInTheDocument();
  expect(screen.queryByText('接口快照 · 0 项')).not.toBeInTheDocument();
}, 15000);
