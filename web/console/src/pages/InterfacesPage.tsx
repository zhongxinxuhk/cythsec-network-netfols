// InterfacesPage.tsx - 网卡 / IP / 接口状态页。
import { api } from '@/api/client';
import type { InterfaceInfo } from '@/api/types';
import { Card } from '@/components/Card';
import { StatusBadge } from '@/components/StatusBadge';
import { useApi } from '@/hooks/useApi';

function ifaceTone(ifc: InterfaceInfo): 'ok' | 'muted' {
  return ifc.up && ifc.running ? 'ok' : 'muted';
}

export function InterfacesPage() {
  const { data, loading, error, reload } = useApi<InterfaceInfo[]>(
    () => api.interfaces(),
    5000, // 5s 轮询，反映接口状态变化
  );
  return (
    <div className="page">
      <Card
        title="网络接口"
        subtitle="网卡、绑定 IP 与接口状态（5s 轮询）"
        loading={loading}
        error={error}
      >
        {data && data.length === 0 && <p className="muted">未发现接口</p>}
        {data &&
          data.map((ifc) => (
            <div className="iface" key={ifc.name}>
              <div className="iface-row">
                <strong>{ifc.name}</strong>
                <StatusBadge
                  tone={ifaceTone(ifc)}
                  label={ifc.up && ifc.running ? 'up / running' : 'down'}
                />
                <span className="mono muted small">{ifc.mac || '—'}</span>
                <span className="muted small">mtu {ifc.mtu}</span>
                {ifc.loopback && <span className="chip">loopback</span>}
              </div>
              {ifc.addresses.length > 0 && (
                <ul className="addr-list">
                  {ifc.addresses.map((a) => (
                    <li key={a.cidr} className="mono small">
                      {a.cidr}
                      <span className="muted"> · {a.scope}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        {!loading && (
          <button className="btn" onClick={reload}>
            立即刷新
          </button>
        )}
      </Card>
    </div>
  );
}
