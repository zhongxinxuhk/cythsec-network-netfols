// RoutesPage.tsx - 路由表页。
import { api } from '@/api/client';
import type { Route } from '@/api/types';
import { Card } from '@/components/Card';
import { useApi } from '@/hooks/useApi';

export function RoutesPage() {
  const { data, loading, error, reload } = useApi<Route[]>(() => api.routes());
  return (
    <div className="page">
      <Card title="路由表" subtitle="IPv4 路由" loading={loading} error={error}>
        {data && data.length === 0 && <p className="muted">当前无 IPv4 路由</p>}
        {data && data.length > 0 && (
          <table className="tbl">
            <thead>
              <tr>
                <th>目的网络</th>
                <th>网关</th>
                <th>掩码</th>
                <th>接口</th>
                <th>metric</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r, i) => (
                <tr key={i}>
                  <td className="mono">{r.destination}</td>
                  <td className="mono">{r.gateway === '0.0.0.0' ? '—' : r.gateway}</td>
                  <td className="mono">{r.mask}</td>
                  <td>{r.interface}</td>
                  <td>{r.metric}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!loading && (
          <button className="btn" onClick={reload}>
            刷新
          </button>
        )}
      </Card>
    </div>
  );
}
