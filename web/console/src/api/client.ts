// client.ts - 调用 routerd /api/v1 的轻量客户端。
// 开发期经 Umi proxy（/api -> http://localhost:8080）转发到 routerd。
import type {
  ApiEnvelope,
  InterfaceInfo,
  Route,
  SystemInfo,
  TrafficCounters,
} from './types';

// routerd 基地址：优先用 构建期注入的配置（见 config/config.ts），
// 缺省走相对 /api（由 dev proxy 或反代指向 routerd）。
import { ApiError, secureFetch } from './http';
export { ApiError } from './http';

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await secureFetch('routerd', path, { signal: AbortSignal.timeout(10000) });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('无法连接 routerd，请确认控制面服务已启动');
  }
  if (!res.ok) {
    throw new ApiError(`HTTP ${res.status}`, res.status);
  }
  const body = (await res.json()) as ApiEnvelope<T>;
  if (body.error) {
    throw new ApiError(body.error);
  }
  return body.data;
}

export const api = {
  system: () => get<SystemInfo>('/system'),
  interfaces: () => get<InterfaceInfo[]>('/interfaces'),
  routes: () => get<Route[]>('/routes'),
  traffic: () => get<TrafficCounters[]>('/traffic'),
};
