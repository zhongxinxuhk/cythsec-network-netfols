import { afterEach, expect, it, vi } from 'vitest';
import { analytics } from './analytics';
afterEach(() => vi.unstubAllGlobals());
it('超过上传上限时不发网络请求', async () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  await expect(analytics.upload(new File([new Uint8Array(1024 * 1024 + 1)], 'large.jsonl'))).rejects.toThrow('1 MiB');
  expect(fetcher).not.toHaveBeenCalled();
});
it('分页参数及取消信号送至 telemetryd 路径', async () => {
  const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ data: { items: [] } }) });
  vi.stubGlobal('fetch', fetcher); const controller = new AbortController();
  await analytics.windows('abc', { from: 0, to: 120, offset: 1, limit: 20 }, controller.signal);
  expect(fetcher).toHaveBeenCalledWith('/telemetry/api/v1/analytics/imports/abc?from=0&to=120&offset=1&limit=20', { signal: controller.signal });
});
it('持久化后端错误不会退化为空历史', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503, json: async () => ({ error: '聚合持久化未启用' }) }));
  await expect(analytics.imports()).rejects.toThrow('聚合持久化未启用');
});
it('队列接口使用独立接收端点并保留 202 阶段', async () => {
  const fetcher = vi.fn().mockResolvedValue({ ok: true, status: 202, json: async () => ({ data: { durable: true, acknowledged_stage: 'queue', id: 'abc', duplicate: false } }) });
  vi.stubGlobal('fetch', fetcher);
  const file = { size: 1, text: async () => 'x' } as File;
  const reply = await analytics.enqueue(file);
  expect(reply.acknowledged_stage).toBe('queue');
  expect(fetcher).toHaveBeenCalledWith('/telemetry/api/v1/analytics/ingest', { method: 'POST', headers: { 'Content-Type': 'application/x-ndjson' }, body: 'x' });
});
