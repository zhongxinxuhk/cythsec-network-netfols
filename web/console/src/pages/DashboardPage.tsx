// DashboardPage.tsx - 概览仪表盘（第一阶段：聚合各端点摘要，不做复杂可视化）。
import { api } from '@/api/client';
import type { InterfaceInfo, Route, SystemInfo } from '@/api/types';
import { Card } from '@/components/Card';
import { useApi } from '@/hooks/useApi';

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="stat">
      <span className="stat-v">{value}</span>
      <span className="stat-k">{label}</span>
      {hint && <span className="stat-h">{hint}</span>}
    </div>
  );
}

export function DashboardPage() {
  const sys = useApi<SystemInfo>(() => api.system());
  const ifaces = useApi<InterfaceInfo[]>(() => api.interfaces());
  const routes = useApi<Route[]>(() => api.routes());

  const upCount = (ifaces.data ?? []).filter((i) => i.up && i.running).length;
  const ifaceCount = (ifaces.data ?? []).length;
  const routeCount = (routes.data ?? []).length;

  return (
    <div className="page">
      <Card title="Dashboard" subtitle="cythsec 概览" loading={sys.loading} error={sys.error}>
        {sys.data && (
          <div className="stat-row">
            <Stat label="主机" value={sys.data.hostname} hint={sys.data.os} />
            <Stat label="路由" value={String(routeCount)} hint="IPv4 路由数" />
            <Stat label="接口" value={String(ifaceCount)} hint={`${upCount} up`} />
          </div>
        )}
      </Card>

      <Card
        title="接口状态"
        loading={ifaces.loading}
        error={ifaces.error}
      >
        {ifaces.data && ifaces.data.length === 0 && <p className="muted">无接口</p>}
        {ifaces.data && ifaces.data.map((i) => (
          <div className="iface" key={i.name}>
            <div className="iface-row">
              <strong>{i.name}</strong>
              <span className={i.up ? 'ok-text small' : 'muted small'}>{i.up ? 'up' : 'down'}</span>
              <span className="muted small">{i.addresses.find((a) => a.scope === 'global')?.ip ?? '—'}</span>
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
}
