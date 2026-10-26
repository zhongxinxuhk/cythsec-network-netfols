import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { IngestStatus } from '@/api/analytics';
import { IngestPanel } from './IngestPanel';
const pending: IngestStatus = {
  enabled: true, running: true, state: 'backoff', pending_batches: 2, pending_bytes: 4096,
  max_batches: 1024, max_bytes: 67108864, oldest_queued_at: '2026-10-26T00:00:00Z',
  next_retry_at: '2026-10-26T00:01:00Z', last_error: 'storage_full', completed_this_process: 0,
  duplicates_this_process: 0, failures_this_process: 1, consecutive_failures: 1,
};
afterEach(cleanup);
it('保留容量失败和待写状态，不将接收当作完成', () => {
  render(<IngestPanel status={pending} error={null} />);
  expect(screen.getByText(/历史存储容量已满，待写批次仍保留/)).toBeInTheDocument();
  expect(screen.getByText(/退避重试中/)).toBeInTheDocument();
  expect(screen.getByText('2')).toBeInTheDocument();
  expect(screen.getByText(/下次重试/)).toBeInTheDocument();
  expect(screen.getByText(/进程计数在重启后归零/)).toBeInTheDocument();
});
it('不可恢复的确认失败要求处理后重启', () => {
  render(<IngestPanel status={{ ...pending, state: 'blocked', last_error: 'queue_ack_failed', next_retry_at: null }} error={null} />);
  expect(screen.getByText(/需要处理后重启/)).toBeInTheDocument();
  expect(screen.getByText(/历史已确认保存，但队列确认失败/)).toBeInTheDocument();
  expect(screen.queryByText(/下次重试/)).not.toBeInTheDocument();
});
it('队列查询失败显示不可用，不能显示零积压', () => {
  render(<IngestPanel status={null} error="服务不可用" />);
  expect(screen.getByText(/上传暂不可用，已有历史仍可查询/)).toBeInTheDocument();
  expect(screen.queryByText(/待写批次/)).not.toBeInTheDocument();
});
