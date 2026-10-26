import { PageContainer, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Space, Tag } from 'antd';
import { api } from '@/api/client';
import type { InterfaceInfo } from '@/api/types';
import { StatusBadge } from '@/components/StatusBadge';
import { useApi } from '@/hooks/useApi';
const columns: ProColumns<InterfaceInfo>[] = [
  { title: '接口名称', dataIndex: 'name', copyable: true },
  { title: '状态', key: 'status', render: (_, item) => <StatusBadge tone={item.up && item.running ? 'ok' : 'muted'} label={item.up && item.running ? 'up / running' : 'down'} /> },
  { title: 'MAC 地址', dataIndex: 'mac', copyable: true },
  { title: 'MTU', dataIndex: 'mtu', valueType: 'digit' },
  { title: '绑定地址', key: 'addresses', render: (_, item) => <Space orientation="vertical">{item.addresses.map((address) => <span className="mono" key={address.cidr}>{address.cidr} <Tag>{address.scope || '未知范围'}</Tag></span>)}</Space> },
  { title: '类型', key: 'type', render: (_, item) => item.loopback ? <Tag>loopback</Tag> : <Tag>网络接口</Tag> },
];
export function InterfacesPage() {
  const { data, loading, error, reload } = useApi(api.interfaces, 5000);
  return <PageContainer content="网卡、绑定 IP 与接口状态，每 5 秒刷新。">
    {error && <Alert type="error" title={error} showIcon role="alert" />}
    <ProTable<InterfaceInfo> headerTitle="网络接口" rowKey="name" columns={columns} dataSource={data ?? []} loading={loading} search={false} pagination={{ pageSize: 10 }} options={{ density: false, reload }} scroll={{ x: 900 }} />
  </PageContainer>;
}
export default InterfacesPage;
