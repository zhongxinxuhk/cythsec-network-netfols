import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { analytics } from '@/api/analytics';
import type { AggregateImport, AggregatePage } from '@/api/analytics';
import { AnalyticsPage } from './AnalyticsPage';
vi.mock('@/api/analytics', () => ({ analytics: { imports: vi.fn(), windows: vi.fn(), upload: vi.fn(), enqueue: vi.fn(), ingest: vi.fn() } }));
const item: AggregateImport = {
  id: 'a'.repeat(64), stored_at: '2026-10-26T00:00:00Z', bytes: 2048, windows: 2,
  first_window_seconds: 0, last_window_seconds: 60,
  status: { input_complete: false, analysis_complete: false, capture_loss_status: 'unknown',
    published_windows: 1, suppressed_windows: 1, source_counter_consistent: null },
};
const page: AggregatePage = { import: item, total: 2, offset: 0, limit: 100, items: [
  { window_start_seconds: 0, window_seconds: 60, sampling_interval: 1, suppressed: true, statistics: null },
  { window_start_seconds: 60, window_seconds: 60, sampling_interval: 1, suppressed: false, statistics: {
    contributing_sampled_flows: 20, tcp_packets: 0, udp_packets: 20, other_ip_packets: 0,
    tls_record_candidate_packets: null, quic_long_header_candidate_packets: null, tcp_quality: null,
    integrity: { records: 20, snaplen_truncated: 0, decode_incomplete: 0, unparsed_fragments: 0,
      fragmented_transport: 0, capacity_rejected_packets: 0, late_records: 0, timestamp_regressions: 0 },
  } },
] };
beforeEach(() => {
  vi.mocked(analytics.ingest).mockResolvedValue({ enabled: false, running: false, state: 'disabled', pending_batches: 0, pending_bytes: 0, max_batches: 0, max_bytes: 0, oldest_queued_at: null, next_retry_at: null, last_error: null, completed_this_process: 0, duplicates_this_process: 0, failures_this_process: 0, consecutive_failures: 0 });
  vi.mocked(analytics.imports).mockResolvedValue({ items: [item], total: 1 });
  vi.mocked(analytics.windows).mockResolvedValue(page);
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });
describe('聚合历史分析', () => {
  it('展示不完整、丢包未知及抑制状态，不把 null 画成零', async () => {
    render(<AnalyticsPage />);
    expect(await screen.findByText(/文件读取：不完整/)).toBeInTheDocument();
    expect(screen.getByText(/来源丢包未知/)).toBeInTheDocument();
    expect(screen.getByText('样本流数不足，统计已抑制')).toBeInTheDocument();
    expect(screen.getByText('未发布 / 未发布')).toBeInTheDocument();
    expect(screen.getByText('0 / 20 / 0')).toBeInTheDocument();
  });
  it('空历史与服务不可用明确分开，并可重试', async () => {
    vi.mocked(analytics.imports).mockRejectedValueOnce(new Error('聚合持久化未启用'));
    render(<AnalyticsPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('聚合持久化未启用');
    expect(screen.queryByText(/尚无聚合历史/)).not.toBeInTheDocument();
    vi.mocked(analytics.imports).mockResolvedValue({ items: [], total: 0 });
    fireEvent.click(screen.getByText('刷新历史'));
    expect(await screen.findByText(/尚无聚合历史/)).toBeInTheDocument();
  });
  it('校验时间范围并将查询限定在选中批次', async () => {
    render(<AnalyticsPage />); await screen.findByText(/文件读取：不完整/);
    fireEvent.change(screen.getByLabelText('起始时间'), { target: { value: '2026-10-26T12:00' } });
    fireEvent.change(screen.getByLabelText('结束时间'), { target: { value: '2026-10-26T11:00' } });
    fireEvent.click(screen.getByText('查询窗口'));
    expect(screen.getByRole('alert')).toHaveTextContent('请选择有效的起止时间');
    expect(analytics.windows).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText('结束时间'), { target: { value: '2026-10-26T13:00' } });
    fireEvent.click(screen.getByText('查询窗口'));
    await waitFor(() => expect(analytics.windows).toHaveBeenCalledTimes(2));
    expect(vi.mocked(analytics.windows).mock.calls[1][0]).toBe(item.id);
    expect(vi.mocked(analytics.windows).mock.calls[1][1]).toMatchObject({ from: new Date('2026-10-26T12:00').getTime() / 1000, offset: 0, limit: 100 });
  });
  it('历史分页有边界，重复导入提示不重复写入', async () => {
    vi.mocked(analytics.windows).mockResolvedValue({ ...page, total: 101 });
    vi.mocked(analytics.upload).mockResolvedValue({ import: item, duplicate: true, durable: true });
    render(<AnalyticsPage />); await screen.findByText(/文件读取：不完整/);
    expect(screen.getByText('上一页')).toBeDisabled();
    fireEvent.click(screen.getByText('下一页'));
    await waitFor(() => expect(analytics.windows).toHaveBeenCalledWith(item.id, expect.objectContaining({ offset: 100 }), expect.any(AbortSignal)));
    fireEvent.change(screen.getByLabelText('导入聚合 JSONL'), { target: { files: [new File(['x'], 'aggregate.jsonl')] } });
    expect(await screen.findByText('该批次已存在，未重复写入')).toBeInTheDocument();
  });
  it('较早批次请求晚返回时不覆盖当前批次', async () => {
    let resolveOld!: (page: AggregatePage) => void;
    vi.mocked(analytics.imports).mockResolvedValue({ items: [item, { ...item, id: 'b'.repeat(64) }], total: 2 });
    vi.mocked(analytics.windows).mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }));
    render(<AnalyticsPage />);
    await waitFor(() => expect(analytics.windows).toHaveBeenCalledTimes(1));
    fireEvent.change(screen.getByLabelText('采集批次'), { target: { value: 'b'.repeat(64) } });
    await screen.findByText(/文件读取：不完整/);
    resolveOld({ ...page, items: [], total: 999 });
    await waitFor(() => expect(screen.getByText(/匹配 2 窗/)).toBeInTheDocument());
    expect(screen.queryByText(/匹配 999 窗/)).not.toBeInTheDocument();
  });
});

it('启用队列时上传只确认待写，不走同步导入', async () => {
  vi.mocked(analytics.ingest).mockResolvedValue({ enabled: true, running: true, state: 'idle', pending_batches: 0, pending_bytes: 0, max_batches: 1024, max_bytes: 67108864, oldest_queued_at: null, next_retry_at: null, last_error: null, completed_this_process: 0, duplicates_this_process: 0, failures_this_process: 0, consecutive_failures: 0 });
  vi.mocked(analytics.enqueue).mockResolvedValue({ id: 'c'.repeat(64), durable: true, duplicate: false, acknowledged_stage: 'queue' });
  render(<AnalyticsPage />); await screen.findByText(/工作进程运行中/);
  fireEvent.change(screen.getByLabelText('导入聚合 JSONL'), { target: { files: [new File(['x'], 'aggregate.jsonl')] } });
  expect(await screen.findByText('已进入持久化待写队列，历史写入尚未确认')).toBeInTheDocument();
  expect(analytics.enqueue).toHaveBeenCalledTimes(1);
  expect(analytics.upload).not.toHaveBeenCalled();
});
it('队列状态失败不静默绕过队列，仍可读取历史', async () => {
  vi.mocked(analytics.ingest).mockRejectedValue(new Error('服务不可用'));
  render(<AnalyticsPage />); await screen.findByText(/队列状态不可用/);
  expect(screen.getByLabelText('导入聚合 JSONL')).toBeDisabled();
  expect(await screen.findByText(/文件读取：不完整/)).toBeInTheDocument();
  expect(analytics.upload).not.toHaveBeenCalled();
});
