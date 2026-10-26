import { PageContainer, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert } from 'antd';
import { api } from '@/api/client';
import type { TrafficCounters } from '@/api/types';
import { useApi } from '@/hooks/useApi';
import { fmtBytes, fmtInt } from '@/utils/format';
const columns: ProColumns<TrafficCounters>[] = [
  { title: '接口', dataIndex: 'interface', fixed: 'left' },
  ...(['rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_dropped', 'tx_dropped', 'rx_errors', 'tx_errors'] as const).map((key) => ({
    title: { rx_bytes: 'RX 字节', tx_bytes: 'TX 字节', rx_packets: 'RX 包', tx_packets: 'TX 包', rx_dropped: 'RX 丢弃', tx_dropped: 'TX 丢弃', rx_errors: 'RX 错误', tx_errors: 'TX 错误' }[key],
    dataIndex: key, renderText: (value: number) => key.endsWith('bytes') ? fmtBytes(value) : fmtInt(value), sorter: (a: TrafficCounters, b: TrafficCounters) => a[key] - b[key],
  })),
];
export function TrafficPage() {
  const { data, loading, error, reload } = useApi(api.traffic, 3000);
  return <PageContainer content="网卡累计 RX / TX 计数，每 3 秒刷新；累计量不作为实时速率。">
    {error && <Alert type="error" title={error} showIcon role="alert" />}
    <ProTable<TrafficCounters> headerTitle="接口流量" rowKey="interface" columns={columns} dataSource={data ?? []} loading={loading} search={false} pagination={{ pageSize: 20 }} options={{ density: false, reload }} scroll={{ x: 1200 }} locale={{ emptyText: '当前无流量统计，接口计数取决于运行平台支持。' }} />
  </PageContainer>;
}
export default TrafficPage;
