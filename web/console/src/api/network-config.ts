import { ApiError, secureFetch } from './http';
export interface StaticRoute { destination: string; gateway: string; metric: number }
export interface NetworkInterfaceDraft { id: string; device: string; mtu: number; addresses: string[]; dns: string[]; search: string[]; routes: StaticRoute[] }
export interface NetworkDraft { backend: 'netplan' | 'networkmanager' | 'openwrt'; interfaces: NetworkInterfaceDraft[] }
export interface NetworkSnapshot { revision: number; stage: 'unconfigured' | 'draft_saved'; updated_at: string | null; config: NetworkDraft }
export interface NetworkState { snapshot: NetworkSnapshot; capabilities: { platform: string; can_preview: boolean; can_observe?: boolean; can_preflight?: boolean; can_save: boolean; can_apply: boolean; store_enabled: boolean; preview_backends: string[] } }
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
  observe: async () => { const value = await request<NetworkObservation>('GET', '/observation'); validateObservation(value); return value; },
  preflight: async (draft: NetworkDraft) => {
    const value = await request<NetworkPreflight>('POST', '/preflight', draft);
    validateObservation(value.observation);
    if (!['blocked', 'review_required'].includes(value.status) || value.can_apply !== false || !Array.isArray(value.issues) || !Array.isArray(value.differences) || value.differences.some(d => !['same', 'different', 'unknown'].includes(d.state) || (d.state === 'unknown' && d.current !== null))) throw new ApiError('应用前检查响应无效');
    return value;
  },
  preview: (draft: NetworkDraft) => request<NetworkPreview>('POST', '/preview', draft),
  save: (draft: NetworkDraft, revision: number) => request<NetworkSnapshot>('PUT', '', draft, revision),
};

export interface NetworkOwner { backend: string; reference: string; source: string }
export interface ObservedNetworkInterface {
  device: string; kind: string; up: boolean; mtu: number | null;
  addresses: string[] | null; dns: string[] | null; search: string[] | null; routes: StaticRoute[] | null;
  owners: NetworkOwner[]; known: Partial<Record<'mtu' | 'addresses' | 'dns' | 'search' | 'routes', boolean>>; sources: Record<string, string>;
}
export interface NetworkObservation {
  id: string; platform: string; started_at: string; observed_at: string; inventory_available: boolean; status: 'partial' | 'observed';
  managers: { backend: string; state: 'active' | 'inactive' | 'partial' | 'unavailable' | 'unsupported'; tool_version: string; diagnostic: string }[];
  interfaces: ObservedNetworkInterface[]; warnings: string[];
}
export interface NetworkCheckIssue { severity: 'blocker' | 'review'; device: string; code: string; message: string }
export interface NetworkFieldDifference { device: string; field: string; current: number | string[] | null; desired: number | string[]; state: 'same' | 'different' | 'unknown'; source: string }
export interface NetworkPreflight { draft_digest: string; observation: NetworkObservation; status: 'blocked' | 'review_required'; can_apply: boolean; issues: NetworkCheckIssue[]; differences: NetworkFieldDifference[] }

function validateObservation(value: NetworkObservation) {
  if (!value || !/^[a-f0-9]{64}$/.test(value.id) || !['partial', 'observed'].includes(value.status) || typeof value.inventory_available !== 'boolean' || !Array.isArray(value.interfaces) || !Array.isArray(value.managers) || !Number.isFinite(Date.parse(value.observed_at)) || value.interfaces.some(p => !p.known || !p.sources || !Array.isArray(p.owners))) throw new ApiError('网络环境响应无效');
}
