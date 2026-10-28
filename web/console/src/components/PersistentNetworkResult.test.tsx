import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
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
  expect(screen.getAllByText('未取得')).toHaveLength(2);
  expect(screen.queryByText('0 B')).not.toBeInTheDocument();
});
