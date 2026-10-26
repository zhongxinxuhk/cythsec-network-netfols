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
