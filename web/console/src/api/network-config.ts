import { ApiError, secureFetch } from './http';
export interface StaticRoute { destination: string; gateway: string; metric: number }
export interface NetworkInterfaceDraft { id: string; device: string; mtu: number; addresses: string[]; dns: string[]; search: string[]; routes: StaticRoute[] }
export interface NetworkDraft { backend: 'netplan' | 'networkmanager' | 'openwrt'; interfaces: NetworkInterfaceDraft[] }
export interface NetworkSnapshot { revision: number; stage: 'unconfigured' | 'draft_saved'; updated_at: string | null; config: NetworkDraft }
export interface NetworkState { snapshot: NetworkSnapshot; capabilities: { platform: string; can_preview: boolean; can_save: boolean; can_apply: boolean; store_enabled: boolean; preview_backends: string[] } }
export interface NetworkPreview { digest: string; stage: 'validated_preview'; artifacts: { name: string; content: string }[] }
async function request<T>(method: string, suffix: string, body?: NetworkDraft, revision?: number): Promise<T> {
  const headers = new Headers();
  if (body) headers.set('Content-Type', 'application/json');
  if (revision !== undefined) headers.set('If-Match', `"${revision}"`);
  let response: Response;
  try { response = await secureFetch('routerd', `/network/configuration${suffix}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10000) }); }
  catch (cause) { if (cause instanceof ApiError) throw cause; throw new ApiError(method === 'PUT' ? '保存请求未完成，请重新读取并核对版本' : '无法完成网络配置请求，请检查服务连接'); }
  let result;
  try { result = await response.json(); } catch { throw new ApiError('网络配置服务响应格式无效'); }
  if (!result || typeof result !== 'object') throw new ApiError('网络配置服务响应格式无效');
  if (!response.ok || result.error) throw new ApiError(result.error || `HTTP ${response.status}`, response.status);
  if (!result.data || typeof result.data !== 'object') throw new ApiError('网络配置响应缺少数据');
  return result.data as T;
}
export const networkConfig = {
  read: () => request<NetworkState>('GET', ''),
  preview: (draft: NetworkDraft) => request<NetworkPreview>('POST', '/preview', draft),
  save: (draft: NetworkDraft, revision: number) => request<NetworkSnapshot>('PUT', '', draft, revision),
};
