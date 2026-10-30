import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { useApi } from './useApi';
afterEach(cleanup);
it('内联 fetcher 随渲染变化不会重复请求，旧请求晚到不会覆盖刷新结果', async () => {
  let complete!: (value: string) => void;
  const request = vi.fn<() => Promise<string>>().mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; })).mockResolvedValue('new');
  const { result, rerender } = renderHook(() => useApi(() => request()));
  rerender();
  expect(request).toHaveBeenCalledTimes(1);
  await act(async () => { result.current.reload(); });
  await waitFor(() => expect(result.current.data).toBe('new'));
  await act(async () => complete('old'));
  expect(result.current.data).toBe('new');
});
