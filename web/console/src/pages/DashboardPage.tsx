import { PageContainer, ProCard } from '@ant-design/pro-components';
import { Alert, Col, Row, Statistic, Table, Typography } from 'antd';
import type { InterfaceInfo } from '@/api/types';
import { api } from '@/api/client';
import { useApi } from '@/hooks/useApi';
import { StatusBadge } from '@/components/StatusBadge';
export function DashboardPage() {
  const sys = useApi(api.system);
  const ifaces = useApi(api.interfaces);
  const routes = useApi(api.routes);
  return <PageContainer content="控制面服务与网络资源概览"><div className="page-stack">
    <Row gutter={[24, 24]}>
      {[
        { title: '运行主机', value: sys.data?.hostname, error: sys.error },
        { title: 'IPv4 路由', value: routes.data?.length, error: routes.error },
        { title: '网络接口', value: ifaces.data?.length, error: ifaces.error },
        { title: '运行中接口', value: ifaces.data?.filter((item) => item.up && item.running).length, error: ifaces.error },
      ].map((item) => <Col key={item.title} xs={24} sm={12} xl={6}><ProCard variant="outlined">
        <Statistic title={item.title} value={item.value ?? '未获取'} />
        {item.error && <Alert type="error" title={item.error} showIcon />}
      </ProCard></Col>)}
    </Row>
    <ProCard title="接口状态" variant="outlined" loading={ifaces.loading}>
      {ifaces.error ? <Alert type="error" title={ifaces.error} showIcon /> : <Table<InterfaceInfo> size="small" rowKey="name" dataSource={ifaces.data ?? []} pagination={false} scroll={{ x: 600 }} locale={{ emptyText: '未发现接口' }} columns={[
        { title: '接口', dataIndex: 'name' },
        { title: '绑定地址', key: 'addresses', render: (_, item) => item.addresses.map((address) => address.cidr).join(' · ') || '未绑定地址' },
        { title: '状态', key: 'state', render: (_, item) => <StatusBadge tone={item.up && item.running ? 'ok' : 'muted'} label={item.up && item.running ? 'up / running' : 'down'} /> },
      ]} />}
    </ProCard>
    <Typography.Paragraph type="secondary">仅展示服务实际返回的数据。接口计数来自系统累计值，聚合分析按采集批次独立查询。</Typography.Paragraph>
  </div></PageContainer>;
}
export default DashboardPage;
