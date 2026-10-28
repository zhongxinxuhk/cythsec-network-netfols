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

export interface PersistentNetworkSource { id: string; path: string; storage: 'persistent' | 'runtime' | 'vendor'; version_tag: string; bytes: number; state: 'read' | 'unavailable' | 'unsupported'; safety?: NetworkSourceSafety }
export type PersistentField = 'mtu' | 'addresses' | 'dns' | 'search' | 'routes';
export interface PersistentNetworkProfile {
  reference: string; device: string; binding: 'declared' | 'unresolved'; methods: Record<string, string>;
  mtu: number | null; addresses: string[] | null; dns: string[] | null; search: string[] | null;
  routes: { destination: string; gateway: string; metric: number | null }[] | null;
  field_states: Record<PersistentField, 'configured' | 'unset' | 'unsupported'>;
  source_ids: string[]; origin_verified: boolean; load_reference?: 'matched' | 'not_observed' | 'conflicting' | 'unknown';
  device_association?: NetworkDeviceAssociation;
  loaded_comparison?: NetworkLoadedComparison;
  routing_comparison?: NetworkRoutingComparison;
}
export interface PersistentNetworkInspection {
  id: string; backend: NetworkDraft['backend']; platform: string; scope: 'merged_ethernets' | 'keyfile_profiles' | 'committed_network';
  observed_at: string; status: 'observed' | 'partial' | 'unavailable' | 'unsupported'; can_apply: false;
  authority?: NetworkAuthorityReport; manager?: NetworkManagerReferences;
  device_evidence?: NetworkDeviceEvidence;
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
    if (s.safety) {
      const a = s.safety;
      if (![a.uid, a.gid].every(v => v === null || Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 4294967295) || !(a.mode === '' || /^0[0-7]{3}$/.test(a.mode)) || !(a.stable === null || typeof a.stable === 'boolean') || !['meets_baseline', 'review', 'blocked', 'unknown'].includes(a.status) || !Array.isArray(a.codes) || a.codes.some(c => typeof c !== 'string')) fail();
    }
    ids.add(s.id);
  }
  for (const p of value.profiles) {
    if (!p || typeof p.reference !== 'string' || !p.reference || p.reference.length > 256 || typeof p.device !== 'string' || !['declared', 'unresolved'].includes(p.binding) || typeof p.origin_verified !== 'boolean' || !Array.isArray(p.source_ids) || !p.source_ids.length || p.source_ids.some(id => !ids.has(id)) || (p.origin_verified && (backend === 'netplan' || p.source_ids.length !== 1 || value.sources.some(s => p.source_ids.includes(s.id) && s.state !== 'read'))) || !p.methods || typeof p.methods !== 'object' || Array.isArray(p.methods) || Object.values(p.methods).some(m => typeof m !== 'string') || !p.field_states) fail();
    if (p.load_reference !== undefined && !['matched', 'not_observed', 'conflicting', 'unknown'].includes(p.load_reference)) fail();
    if (p.device_association) {
      const a = p.device_association;
      const state = a.device_state;
      if (!['active', 'inactive', 'transitioning', 'unmanaged', 'unavailable_device', 'not_observed', 'conflicting', 'unknown'].includes(a.state) || !(state === null || Number.isInteger(state) && state >= 0 && state <= 120 && state % 10 === 0) || ![a.managed, a.active_profile_matches].every(v => v === null || typeof v === 'boolean')) fail();
      if (state === null || state === 0) {
        if (a.managed !== null || a.active_profile_matches !== null || !['unknown', 'not_observed'].includes(a.state) || a.state === 'not_observed' && state !== null) fail();
      } else {
        if (a.managed !== (state !== 10)) fail();
        const expected = state === 10 ? 'unmanaged' : a.active_profile_matches === false ? 'conflicting' : state === 100 ? a.active_profile_matches === true ? 'active' : 'unknown' : state === 20 ? 'unavailable_device' : state === 30 || state === 120 ? 'inactive' : 'transitioning';
        if (a.state !== expected) fail();
      }
      if ((a.state !== 'unknown' || state !== null) && (backend !== 'networkmanager' || p.binding !== 'declared' || !p.device || !/^nm:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(p.reference) || value.device_evidence?.state !== 'observed')) fail();
      if (value.device_evidence?.state !== 'observed' && state !== null) fail();
    }
    if (p.loaded_comparison) {
      const c = p.loaded_comparison;
      const names = ['device', 'mtu', 'ipv4_method', 'ipv6_method', 'addresses', 'dns', 'search'];
      if (!['partial', 'different', 'unavailable', 'unsupported', 'not_checked'].includes(c.state) || c.scope !== 'nm_profile_scalar_and_sets' || typeof c.observed_at !== 'string' || !Number.isFinite(Date.parse(c.observed_at)) || typeof c.diagnostic !== 'string' || !Array.isArray(c.fields)) fail();
      const observed = c.state === 'partial' || c.state === 'different';
      if (observed && (backend !== 'networkmanager' || value.platform !== 'linux' || p.load_reference !== 'matched' || !p.origin_verified || !/^nm:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(p.reference)) || c.fields.length !== (observed ? names.length : 0)) fail();
      for (const [i, f] of c.fields.entries()) {
        if (!f || f.field !== names[i] || !['same', 'different', 'unknown'].includes(f.state) || !['compared', 'source_unset_or_unsupported', 'loaded_field_unsupported'].includes(f.reason)) fail();
        const valid = (v: unknown, loaded: boolean) => v === null || (f.field === 'mtu' ? typeof v === 'number' && Number.isInteger(v) && v >= (loaded ? 0 : 1) && v <= 65536 : ['addresses', 'dns', 'search'].includes(f.field) ? Array.isArray(v) && v.length <= 256 && v.every(s => typeof s === 'string' && s.length <= 253) : typeof v === 'string' && v.length > 0 && v.length <= 64);
        if (!valid(f.source, false) || !valid(f.loaded, true)) fail();
        const method = p.methods[f.field === 'ipv4_method' ? 'ipv4' : 'ipv6'];
        const expectedSource = f.field === 'device' ? p.binding === 'declared' ? p.device : null : f.field === 'mtu' ? p.field_states.mtu === 'configured' ? p.mtu : null : ['ipv4_method', 'ipv6_method'].includes(f.field) ? method && !['unknown', 'unspecified'].includes(method) ? method : null : p.field_states[f.field as PersistentField] === 'configured' ? [...new Set(p[f.field as 'addresses' | 'dns' | 'search'] ?? [])].sort() : null;
        if (JSON.stringify(f.source) !== JSON.stringify(expectedSource)) fail();
        if (f.state === 'unknown') {
          if (f.reason === 'compared' || f.reason === 'source_unset_or_unsupported' && f.source !== null || f.reason === 'loaded_field_unsupported' && f.loaded !== null) fail();
        } else if (f.source === null || f.loaded === null || f.reason !== 'compared' || (f.state === 'same') !== (JSON.stringify(f.source) === JSON.stringify(f.loaded))) fail();
      }
      if (observed && (c.state === 'different') !== c.fields.some(f => f.state === 'different')) fail();
    }
    for (const key of ['mtu', 'addresses', 'dns', 'search', 'routes'] as const) {
      if (!['configured', 'unset', 'unsupported'].includes(p.field_states[key])) fail();
      const field = p[key];
      if (p.field_states[key] !== 'configured' && field !== null) fail();
      if (p.field_states[key] === 'configured') {
        if (key === 'mtu') { if (typeof field !== 'number' || !Number.isInteger(field) || field < 1 || field > 65536) fail(); }
        else if (!Array.isArray(field) || field.length > 256 || (key === 'routes' ? field.some(r => typeof r !== 'object' || !r || !('destination' in r) || typeof r.destination !== 'string' || !('gateway' in r) || typeof r.gateway !== 'string' || !('metric' in r) || !(r.metric === null || typeof r.metric === 'number' && Number.isInteger(r.metric) && r.metric >= 0 && r.metric <= 4294967295)) : field.some(v => typeof v !== 'string'))) fail();
      }
    }
    if (p.routing_comparison) {
      const c = p.routing_comparison;
      const values = (v: unknown) => v === null || Array.isArray(v) && v.length <= 256 && v.every(s => typeof s === 'string' && s.length > 0 && s.length <= 253);
      const expected = p.field_states.routes === 'configured' ? (p.routes ?? []).map(r => `${r.destination} via ${r.gateway} metric ${r.metric === null ? 'default' : r.metric}`).sort() : null;
      if (!['same', 'different', 'unknown', 'unavailable', 'unsupported', 'not_checked'].includes(c.state) || c.scope !== 'nm_declared_route_multiset' || typeof c.observed_at !== 'string' || !Number.isFinite(Date.parse(c.observed_at)) || !['reference_not_matched', 'unsupported_platform', 'backend_not_supported', 'routing_query_unavailable', 'routing_schema_unsupported', 'profile_not_observed', 'loaded_route_semantics_unsupported', 'source_unset_or_unsupported', 'compared_partial_semantics'].includes(c.reason) || !values(c.source) || !values(c.loaded) || JSON.stringify(c.source) !== JSON.stringify(expected)) fail();
      if (['same', 'different', 'unknown'].includes(c.state) && (backend !== 'networkmanager' || value.platform !== 'linux' || p.load_reference !== 'matched' || !p.origin_verified || !/^nm:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(p.reference))) fail();
      if (c.loaded !== null && JSON.stringify(c.loaded) !== JSON.stringify([...c.loaded].sort())) fail();
      if (c.state === 'same' || c.state === 'different') {
        if (c.source === null || c.loaded === null || c.reason !== 'compared_partial_semantics' || (c.state === 'same') !== (JSON.stringify(c.source) === JSON.stringify(c.loaded))) fail();
      } else if (c.state === 'unknown') {
        if (!(c.reason === 'source_unset_or_unsupported' && c.source === null && c.loaded !== null || c.reason === 'loaded_route_semantics_unsupported' && c.loaded === null)) fail();
      } else if (c.loaded !== null || c.reason === 'compared_partial_semantics') fail();
    }
  }
  if (value.manager && (!['observed', 'inactive', 'unavailable', 'unsupported', 'not_checked'].includes(value.manager.state) || value.manager.scope !== 'visible_profile_references' || typeof value.manager.observed_at !== 'string' || !Number.isFinite(Date.parse(value.manager.observed_at)) || typeof value.manager.diagnostic !== 'string')) fail();
  if (value.device_evidence) {
    const e = value.device_evidence;
    if (!['observed', 'inactive', 'unavailable', 'unsupported', 'not_checked'].includes(e.state) || e.scope !== 'visible_nm_device_associations' || typeof e.observed_at !== 'string' || !Number.isFinite(Date.parse(e.observed_at)) || typeof e.diagnostic !== 'string' || e.state === 'observed' && (backend !== 'networkmanager' || value.platform !== 'linux')) fail();
  }
  if (value.authority) {
    const a = value.authority;
    if (!['blocked', 'review_required'].includes(a.status) || a.can_adopt !== false || !Array.isArray(a.issues) || a.issues.some(i => !i || !['blocker', 'review'].includes(i.severity) || typeof i.code !== 'string' || typeof i.message !== 'string' || typeof i.reference !== 'string' || (i.source_id !== '' && !ids.has(i.source_id))) || a.status === 'review_required' && a.issues.some(i => i.severity === 'blocker')) fail();
  }
}

export interface NetworkSourceSafety {
  uid: number | null; gid: number | null; mode: string; stable: boolean | null;
  status: 'meets_baseline' | 'review' | 'blocked' | 'unknown'; codes: string[];
}
export interface NetworkManagerReferences {
  state: 'observed' | 'inactive' | 'unavailable' | 'unsupported' | 'not_checked'; scope: 'visible_profile_references'; observed_at: string; diagnostic: string;
}
export interface NetworkAuthorityReport {
  status: 'blocked' | 'review_required'; can_adopt: false;
  issues: { source_id: string; reference: string; severity: 'blocker' | 'review'; code: string; message: string }[];
}

export interface NetworkDeviceEvidence {
  state: 'observed' | 'inactive' | 'unavailable' | 'unsupported' | 'not_checked'; scope: 'visible_nm_device_associations'; observed_at: string; diagnostic: string;
}
export interface NetworkDeviceAssociation {
  state: 'active' | 'inactive' | 'transitioning' | 'unmanaged' | 'unavailable_device' | 'not_observed' | 'conflicting' | 'unknown';
  device_state: number | null; managed: boolean | null; active_profile_matches: boolean | null;
}

export interface NetworkLoadedComparison {
  state: 'partial' | 'different' | 'unavailable' | 'unsupported' | 'not_checked'; scope: 'nm_profile_scalar_and_sets'; observed_at: string; diagnostic: string;
  fields: { field: 'device' | 'mtu' | 'ipv4_method' | 'ipv6_method' | 'addresses' | 'dns' | 'search'; state: 'same' | 'different' | 'unknown'; reason: string; source: number | string | string[] | null; loaded: number | string | string[] | null }[];
}

export interface NetworkRoutingComparison {
  state: 'same' | 'different' | 'unknown' | 'unavailable' | 'unsupported' | 'not_checked'; scope: 'nm_declared_route_multiset'; observed_at: string; reason: string;
  source: string[] | null; loaded: string[] | null;
}
