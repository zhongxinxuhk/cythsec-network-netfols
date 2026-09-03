// client.ts - 调用 routerd /api/v1 的轻量客户端。
// 开发期经 Vite proxy（/api -> http://localhost:8080）转发到 routerd。
import type {
  ApiEnvelope,
  InterfaceInfo,
  Route,
  SystemInfo,
} from './types';

// routerd 基地址：优先用 Vite 注入的 env（见 vite.config proxy），
// 缺省走相对 /api（由 dev proxy 或反代指向 routerd）。
const BASE = (import.meta.env.VITE_ROUTERD_BASE as string) || '/api/v1';

export class ApiError extends Error {
  constructor(
    message: string,
    public status?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`);
  } catch {
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
};
