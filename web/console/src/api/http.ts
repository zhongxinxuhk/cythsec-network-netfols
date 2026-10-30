export class ApiError extends Error {
  constructor(message: string, public status?: number) { super(message); this.name = 'ApiError'; }
}
export type Service = 'routerd' | 'telemetryd';
export interface AccessIdentity { enabled: boolean; name?: string; role?: 'viewer' | 'operator' | 'admin'; can_ingest: boolean }
const credentials: Partial<Record<Service, string>> = {};
const publicReads = new Set<Service>();
let revision = 0;
const listeners = new Set<() => void>();
export const accessRevision = () => revision;
export const subscribeAccess = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
function changed() { revision++; listeners.forEach((listener) => { listener(); }); }
export function disconnect(service: Service) { delete credentials[service]; publicReads.delete(service); changed(); }
function base(service: Service) { return service === 'routerd' ? __ROUTERD_BASE__ : __TELEMETRYD_BASE__; }

function requireSafeTransport(service: Service) {
  const destination = new URL(base(service), window.location.href);
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(destination.hostname);
  if (destination.protocol !== 'https:' && !(destination.protocol === 'http:' && local)) throw new ApiError('服务认证只允许 HTTPS 或本机回环地址');
}
// Credentials never enter URLs, browser persistence or a different service's request.
export async function secureFetch(service: Service, path: string, init?: RequestInit): Promise<Response> {
  const epoch = revision;
  const current = credentials[service];
  const headers = new Headers(init?.headers);
  if (current) { requireSafeTransport(service); headers.set('Authorization', `Bearer ${current}`); }
  const response = await fetch(`${base(service)}${path}`, { ...init, headers, cache: 'no-store', redirect: 'error' });
  if (epoch !== revision) throw new ApiError('访问身份已变化，请重新读取数据', 401);
  if (response.status === 401 && (current || publicReads.has(service))) disconnect(service);
  if (response.ok && !current) publicReads.add(service);
  return response;
}
async function decodeIdentity(response: Response): Promise<AccessIdentity> {
  if (!response.ok) throw new ApiError(response.status === 401 ? '需要服务访问凭据' : `认证服务 HTTP ${response.status}`, response.status);
  const body = await response.json();
  const identity = body.data as AccessIdentity | undefined;
  if (body.error || !identity || typeof identity.enabled !== 'boolean' || typeof identity.can_ingest !== 'boolean' ||
      (identity.enabled && (typeof identity.name !== 'string' || !identity.name || !['viewer', 'operator', 'admin'].includes(identity.role || '')))) throw new ApiError('认证服务响应无效');
  return identity;
}
export async function serviceAccess(service: Service) {
  const epoch = revision;
  const identity = await decodeIdentity(await secureFetch(service, '/session', { signal: AbortSignal.timeout(5000) }));
  if (epoch !== revision) throw new ApiError('访问身份已变化，请重新读取数据', 401);
  if (!identity.enabled) {
    publicReads.add(service);
    if (credentials[service]) { delete credentials[service]; changed(); }
  }
  return identity;
}
export async function connect(service: Service, credential: string) {
  requireSafeTransport(service);
  if (!/^[\x21-\x7e]{32,256}$/.test(credential)) throw new ApiError('访问凭据须为 32～256 个可打印字符');
  const epoch = revision;
  const response = await fetch(`${base(service)}/session`, { headers: { Authorization: `Bearer ${credential}` }, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(5000) });
  const identity = await decodeIdentity(response);
  if (epoch !== revision) throw new ApiError('访问身份已变化，请重新连接');
  if (!identity.enabled) throw new ApiError('该服务未启用鉴权，无需提交凭据');
  credentials[service] = credential;
  publicReads.delete(service);
  changed();
}
