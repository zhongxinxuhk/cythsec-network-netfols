import { ApiError, secureFetch } from './http';

export type DpiIntensity = 'off' | 'basic' | 'standard' | 'deep';
export type DpiAvailability = 'implemented' | 'context' | 'candidate';

export interface DpiModule {
  key: string;
  name: string;
  group: string;
  availability: DpiAvailability;
  catalog_ids: string[];
  default_enabled: boolean;
  note?: string;
}

export interface DpiPolicy {
  schema_version: 1;
  enabled: boolean;
  intensity: DpiIntensity;
  inspect_bytes: number | null;
  modules: Record<string, boolean>;
  tls_decrypt: { enabled: boolean; keylog_file: string };
}

export interface DpiSnapshot {
  revision: number;
  updated_at: string | null;
  policy: DpiPolicy;
}

export interface DpiState {
  snapshot: DpiSnapshot;
  capabilities: { can_save: boolean; store_enabled: boolean };
}

async function request<T>(method: 'GET' | 'PUT', path: string, body?: unknown, revision?: number): Promise<T> {
  const headers = new Headers();
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  if (revision !== undefined) headers.set('If-Match', `"${revision}"`);
  let response: Response;
  try {
    response = await secureFetch('routerd', path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
  } catch (cause) {
    if (cause instanceof ApiError) throw cause;
    throw new ApiError(method === 'PUT' ? 'DPI 策略保存请求未完成，请重新读取后核对' : '无法读取 DPI 策略，请检查 routerd 服务');
  }
  let result: { data?: T; error?: string };
  try { result = await response.json(); } catch { throw new ApiError('DPI 策略服务响应格式无效'); }
  if (!result || typeof result !== 'object') throw new ApiError('DPI 策略服务响应格式无效');
  if (!response.ok || result.error) {
    if (response.status === 412) throw new ApiError('策略版本已变化，请重新读取后再保存', 412);
    if (response.status === 428) throw new ApiError('缺少策略版本，请重新读取后再保存', 428);
    throw new ApiError(result.error || `HTTP ${response.status}`, response.status);
  }
  if (result.data === undefined) throw new ApiError('DPI 策略响应缺少数据');
  return result.data;
}

export const dpiPolicy = {
  read: () => request<DpiState>('GET', '/dpi/policy'),
  modules: () => request<{ schema_version: number; modules: DpiModule[] }>('GET', '/dpi/modules'),
  save: (policy: DpiPolicy, revision: number) => request<DpiSnapshot>('PUT', '/dpi/policy', policy, revision),
};
