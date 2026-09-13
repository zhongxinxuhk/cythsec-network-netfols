// api-client.test.ts - routerd API 客户端的错误映射测试。
// 该客户端是前端与后端之间唯一的故障边界：它把「fetch 抛错 / HTTP 非 2xx / 业务错误 / 成功」
// 四种情况收敛为统一的 ApiError 与数据返回值。分类错了会导致界面显示错误的故障原因，
// 因此四种路径逐一断言。
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '@/api/client';

/** 构造一个最小的 fetch Response 替身：只提供被测代码实际读取的 ok / status / json。 */
function fakeResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => body,
  } as unknown as Response;
}

describe('api client', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('成功时解包 envelope，只返回 data', async () => {
    const sys = { hostname: 'cythsec-host', os: 'linux', arch: 'amd64', go_version: 'go1.22', pid: 42 };
    fetchMock.mockResolvedValue(fakeResponse({ data: sys }));

    await expect(api.system()).resolves.toEqual(sys);
  });

  it('请求路径基于 /api/v1 前缀拼接', async () => {
    fetchMock.mockResolvedValue(fakeResponse({ data: [] }));

    await api.routes();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/routes');
  });

  it('网络层失败（routerd 未启动）映射为可操作的中文提示', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(api.interfaces()).rejects.toThrow(ApiError);
    await expect(api.interfaces()).rejects.toThrow('无法连接 routerd，请确认控制面服务已启动');
  });

  it('HTTP 非 2xx 时保留状态码，便于界面区分服务端故障', async () => {
    fetchMock.mockResolvedValue(fakeResponse({}, { ok: false, status: 500 }));

    const err = await api.traffic().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(500);
    expect((err as ApiError).message).toBe('HTTP 500');
  });

  it('HTTP 200 但 envelope 内含 error 字段时，按业务错误抛出', async () => {
    fetchMock.mockResolvedValue(fakeResponse({ data: null, error: '读取路由表失败：权限不足' }));

    await expect(api.routes()).rejects.toThrow('读取路由表失败：权限不足');
  });
});
