// TrafficPage.tsx - 网卡流量统计（累计计数器）。
import { api } from '@/api/client';
import type { TrafficCounters } from '@/api/types';
import { Card } from '@/components/Card';
import { useApi } from '@/hooks/useApi';
import { fmtBytes, fmtInt } from '@/utils/format';

export function TrafficPage() {
  const { data, loading, error } = useApi<TrafficCounters[]>(() => api.traffic(), 3000);

  return (
    <div className="page">
      <Card
        title="Traffic"
        subtitle="网卡累计流量计数（rx/tx 字节与包，3s 轮询）"
        loading={loading}
        error={error}
      >
        {data && data.length === 0 && (
          <p className="muted">当前无流量统计（Linux 通过 /sys/class/net 读取，openEuler 上应有数据）</p>
        )}
        {data && data.length > 0 && (
          <table className="tbl">
            <thead>
              <tr>
                <th>接口</th>
                <th>RX 字节</th>
                <th>TX 字节</th>
                <th>RX 包</th>
                <th>TX 包</th>
                <th>RX 丢弃</th>
                <th>TX 丢弃</th>
              </tr>
            </thead>
            <tbody>
              {data.map((t) => (
                <tr key={t.interface}>
                  <td>{t.interface}</td>
                  <td className="mono">{fmtBytes(t.rx_bytes)}</td>
                  <td className="mono">{fmtBytes(t.tx_bytes)}</td>
                  <td className="mono">{fmtInt(t.rx_packets)}</td>
                  <td className="mono">{fmtInt(t.tx_packets)}</td>
                  <td className="mono">{t.rx_dropped}</td>
                  <td className="mono">{t.tx_dropped}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
