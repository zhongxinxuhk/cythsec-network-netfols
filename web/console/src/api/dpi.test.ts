import { afterEach, expect, it, vi } from 'vitest';
import { dpiPolicy } from './dpi';

afterEach(() => vi.unstubAllGlobals());

it('保存策略时发送 If-Match 版本与 JSON body', async () => {
  const fetcher = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ data: { revision: 5, updated_at: null, policy: {} } }) });
  vi.stubGlobal('fetch', fetcher);
  await dpiPolicy.save({
    schema_version: 1, enabled: true, intensity: 'standard', inspect_bytes: null,
    modules: { tls: true }, tls_decrypt: { enabled: false, keylog_file: '' },
  }, 4);
  const [path, init] = fetcher.mock.calls[0];
  expect(path).toBe('/api/v1/dpi/policy');
  expect(init.method).toBe('PUT');
  expect(new Headers(init.headers).get('If-Match')).toBe('"4"');
  expect(JSON.parse(init.body)).toMatchObject({ schema_version: 1, intensity: 'standard' });
});

it('版本冲突保留 412 语义并给可操作提示', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 412, json: async () => ({ error: 'stale' }) }));
  await expect(dpiPolicy.save({
    schema_version: 1, enabled: true, intensity: 'off', inspect_bytes: null,
    modules: {}, tls_decrypt: { enabled: false, keylog_file: '' },
  }, 1)).rejects.toThrow('策略版本已变化，请重新读取后再保存');
});

it('读取失败不退化为空策略', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503, json: async () => ({ error: 'DPI 策略存储未启用' }) }));
  await expect(dpiPolicy.read()).rejects.toThrow('DPI 策略存储未启用');
});
