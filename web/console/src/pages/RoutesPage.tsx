import { PageContainer, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert } from 'antd';
import { api } from '@/api/client';
import type { Route } from '@/api/types';
import { useApi } from '@/hooks/useApi';
const columns: ProColumns<Route>[] = [
  { title: '目的网络', dataIndex: 'destination', copyable: true },
  { title: '网关', dataIndex: 'gateway', renderText: (value: string) => value === '0.0.0.0' ? '直连' : value },
  { title: '掩码', dataIndex: 'mask' },
  { title: '接口', dataIndex: 'interface' },
  { title: 'Metric', dataIndex: 'metric', valueType: 'digit', sorter: (a, b) => a.metric - b.metric },
];
export function RoutesPage() {
  const { data, loading, error, reload } = useApi(api.routes);
  return <PageContainer content="当前主机的 IPv4 路由，只读查询。">
    {error && <Alert type="error" title={error} showIcon role="alert" />}
    <ProTable<Route> headerTitle="路由表" rowKey={(item) => [item.interface, item.destination, item.gateway, item.mask, item.metric, item.flags].join('/')} columns={columns} dataSource={data ?? []} loading={loading} search={false} pagination={{ pageSize: 20 }} options={{ density: false, reload }} scroll={{ x: 800 }} />
  </PageContainer>;
}
export default RoutesPage;
