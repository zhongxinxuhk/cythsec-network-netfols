import { ApiError, secureFetch } from './http';
export interface StaticRoute { destination: string; gateway: string; metric: number }
export interface NetworkInterfaceDraft { id: string; device: string; mtu: number; addresses: string[]; dns: string[]; search: string[]; routes: StaticRoute[] }
export interface NetworkDraft { backend: 'netplan' | 'networkmanager' | 'openwrt'; interfaces: NetworkInterfaceDraft[] }
export interface NetworkSnapshot { revision: number; stage: 'unconfigured' | 'draft_saved'; updated_at: string | null; config: NetworkDraft }
export interface NetworkState { snapshot: NetworkSnapshot; capabilities: { platform: string; can_preview: boolean; can_observe?: boolean; can_preflight?: boolean; can_validate_native?: boolean; can_inspect_persistent?: boolean; can_save: boolean; can_apply: boolean; store_enabled: boolean; preview_backends: string[] } }
export interface NetworkPreview { digest: string; stage: 'validated_preview'; artifacts: { name: string; content: string }[] }
async function request<T>(method: string, suffix: string, body?: NetworkDraft | { backend: NetworkDraft['backend'] }, revision?: number): Promise<T> {
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
  inspectPersistent: async (backend: NetworkDraft['backend']) => {
    const value = await request<PersistentNetworkInspection>('POST', '/persistent-inspection', { backend });
    validatePersistentInspection(value, backend);
    return value;
  },
  observe: async () => { const value = await request<NetworkObservation>('GET', '/observation'); validateObservation(value); return value; },
  preflight: async (draft: NetworkDraft) => {
    const value = await request<NetworkPreflight>('POST', '/preflight', draft);
    validateObservation(value.observation);
    if (!['blocked', 'review_required'].includes(value.status) || value.can_apply !== false || !Array.isArray(value.issues) || !Array.isArray(value.differences) || value.differences.some(d => !['same', 'different', 'unknown'].includes(d.state) || (d.state === 'unknown' && d.current !== null))) throw new ApiError('应用前检查响应无效');
    return value;
  },
  validateNative: async (draft: NetworkDraft) => {
    const value = await request<NetworkNativeValidation>('POST', '/native-validation', draft);
    const names = draft.backend === 'networkmanager' ? draft.interfaces.map(p => `cythsec-${p.id}.nmconnection`) : [draft.backend === 'netplan' ? '90-cythsec.yaml' : 'network.cythsec.uci'];
    if (!value || value.backend !== draft.backend || typeof value.platform !== 'string' || !value.platform || typeof value.tool_version !== 'string' || !/^[a-f0-9]{64}$/.test(value.draft_digest) || value.can_apply !== false || !Number.isFinite(Date.parse(value.checked_at)) || !['parser', 'offline_profile'].includes(value.scope) || !['passed', 'rejected', 'unavailable', 'unsupported'].includes(value.status) || !Array.isArray(value.checks) || value.checks.length !== names.length || value.checks.some((c, i) => !c || c.artifact !== names[i] || !['passed', 'rejected', 'unavailable', 'unsupported'].includes(c.state) || typeof c.message !== 'string' || !c.message || typeof c.code !== 'string') || (value.status === 'passed' && value.checks.some(c => c.state !== 'passed')) || (value.status !== 'passed' && value.checks.every(c => c.state === 'passed'))) throw new ApiError('原生配置校验响应无效');
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

export interface NetworkNativeValidation {
  draft_digest: string; backend: NetworkDraft['backend']; platform: string; checked_at: string;
  status: 'passed' | 'rejected' | 'unavailable' | 'unsupported'; scope: 'parser' | 'offline_profile'; tool_version: string; can_apply: false;
  checks: { artifact: string; state: NetworkNativeValidation['status']; code: string; message: string }[];
}

export interface PersistentNetworkSource { id: string; path: string; storage: 'persistent' | 'runtime' | 'vendor'; version_tag: string; bytes: number; state: 'read' | 'unavailable' | 'unsupported' }
export type PersistentField = 'mtu' | 'addresses' | 'dns' | 'search' | 'routes';
export interface PersistentNetworkProfile {
  reference: string; device: string; binding: 'declared' | 'unresolved'; methods: Record<string, string>;
  mtu: number | null; addresses: string[] | null; dns: string[] | null; search: string[] | null;
  routes: { destination: string; gateway: string; metric: number | null }[] | null;
  field_states: Record<PersistentField, 'configured' | 'unset' | 'unsupported'>;
  source_ids: string[]; origin_verified: boolean;
}
export interface PersistentNetworkInspection {
  id: string; backend: NetworkDraft['backend']; platform: string; scope: 'merged_ethernets' | 'keyfile_profiles' | 'committed_network';
  observed_at: string; status: 'observed' | 'partial' | 'unavailable' | 'unsupported'; can_apply: false;
  sources: PersistentNetworkSource[]; profiles: PersistentNetworkProfile[]; warnings: string[];
}
function validatePersistentInspection(value: PersistentNetworkInspection, backend: NetworkDraft['backend']) {
  const hash = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
  const fail = () => { throw new ApiError('持久配置来源响应无效'); };
  if (!value || !hash(value.id) || value.backend !== backend || typeof value.platform !== 'string' || !value.platform || value.scope !== { netplan: 'merged_ethernets', networkmanager: 'keyfile_profiles', openwrt: 'committed_network' }[backend] || typeof value.observed_at !== 'string' || !Number.isFinite(Date.parse(value.observed_at)) || !['observed', 'partial', 'unavailable', 'unsupported'].includes(value.status) || value.can_apply !== false || !Array.isArray(value.sources) || value.sources.length > 64 || !Array.isArray(value.profiles) || value.profiles.length > 256 || !Array.isArray(value.warnings) || value.warnings.some(w => typeof w !== 'string')) fail();
  if (['unavailable', 'unsupported'].includes(value.status) && value.profiles.length) fail();
  const ids = new Set<string>();
  for (const s of value.sources) {
    if (!s || !hash(s.id) || ids.has(s.id) || typeof s.path !== 'string' || !s.path.startsWith('/') || s.path.length > 4096 || !['persistent', 'runtime', 'vendor'].includes(s.storage) || !['read', 'unavailable', 'unsupported'].includes(s.state) || !Number.isInteger(s.bytes) || s.bytes < 0 || s.bytes > 1048576 || (s.state === 'unavailable' ? s.version_tag !== '' : !hash(s.version_tag))) fail();
    ids.add(s.id);
  }
  for (const p of value.profiles) {
    if (!p || typeof p.reference !== 'string' || !p.reference || p.reference.length > 256 || typeof p.device !== 'string' || !['declared', 'unresolved'].includes(p.binding) || typeof p.origin_verified !== 'boolean' || !Array.isArray(p.source_ids) || !p.source_ids.length || p.source_ids.some(id => !ids.has(id)) || (p.origin_verified && (backend === 'netplan' || p.source_ids.length !== 1 || value.sources.some(s => p.source_ids.includes(s.id) && s.state !== 'read'))) || !p.methods || typeof p.methods !== 'object' || Array.isArray(p.methods) || Object.values(p.methods).some(m => typeof m !== 'string') || !p.field_states) fail();
    for (const key of ['mtu', 'addresses', 'dns', 'search', 'routes'] as const) {
      if (!['configured', 'unset', 'unsupported'].includes(p.field_states[key])) fail();
      const field = p[key];
      if (p.field_states[key] !== 'configured' && field !== null) fail();
      if (p.field_states[key] === 'configured') {
        if (key === 'mtu') { if (typeof field !== 'number' || !Number.isInteger(field) || field < 1 || field > 65536) fail(); }
        else if (!Array.isArray(field) || field.length > 256 || (key === 'routes' ? field.some(r => typeof r !== 'object' || !r || !('destination' in r) || typeof r.destination !== 'string' || !('gateway' in r) || typeof r.gateway !== 'string' || !('metric' in r) || !(r.metric === null || typeof r.metric === 'number' && Number.isInteger(r.metric) && r.metric >= 0 && r.metric <= 4294967295)) : field.some(v => typeof v !== 'string'))) fail();
      }
    }
  }
}
