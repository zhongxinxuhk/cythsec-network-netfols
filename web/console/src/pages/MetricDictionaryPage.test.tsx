import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { aggregateMetrics } from '@/constants/aggregate-metrics';
import MetricDictionaryPage from './MetricDictionaryPage';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('字段字典按真实查询投影搜索并保留候选、可空与采样口径，不请求业务数据', () => {
  const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
  render(<MetricDictionaryPage />);
  expect(screen.queryByText('否；父对象仍可能因抑制而未发布')).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: '搜索指标' }), { target: { value: 'tls_record_candidate_packets' } });
  fireEvent.click(screen.getByRole('button', { name: 'TLS记录头候选' }));
  expect(screen.getByRole('navigation', { name: '指标分类' })).toHaveTextContent('承载统计');
  expect(screen.getByText(/不是TLS会话数、具体应用或VPN数量/)).toBeInTheDocument();
  expect(screen.getByText('是；未发布时保留空值')).toBeInTheDocument();
  expect(screen.getByText('整窗与TLS子组均满足最小流数。')).toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
  expect(new Set(aggregateMetrics.map(metric => metric.field)).size).toBe(aggregateMetrics.length);
}, 15000);
it('不存在的字段保留空结果，不伪造未发布的生产者指标', () => {
  render(<MetricDictionaryPage />);
  fireEvent.change(screen.getByRole('textbox', { name: '搜索指标' }), { target: { value: 'judged_segments' } });
  expect(screen.getByText('字段清单 · 0 项')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '重传候选' })).not.toBeInTheDocument();
});
