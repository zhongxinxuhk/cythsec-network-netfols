import { PageContainer, ProCard, ProTable } from '@ant-design/pro-components';
import {
  Alert,
  Button,
  Col,
  Descriptions,
  Row,
  Space,
  Statistic,
  Tag,
} from 'antd';
import type { ReactNode } from 'react';
import { api } from '@/api/client';
import { useApi } from '@/hooks/useApi';
import { fmtBytes, fmtInt } from '@/utils/format';

function Page({
  title,
  error,
  reload,
  children,
}: {
  title: string;
  error: string | null;
  reload: () => void;
  children: ReactNode;
}) {
  return (
    <PageContainer title={title} extra={<Button onClick={reload}>刷新</Button>}>
      <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
        {error && <Alert type="error" title={error} showIcon />}
        {children}
      </Space>
    </PageContainer>
  );
}

export function Overview() {
  const system = useApi(api.system);
  const interfaces = useApi(api.interfaces);
  const routes = useApi(api.routes);
  return (
    <Page
      title="运行概览"
      error={system.error || interfaces.error || routes.error}
      reload={() => {
        system.reload();
        interfaces.reload();
        routes.reload();
      }}
    >
      <Row gutter={[16, 16]}>
        <Col xs={24} md={8}>
          <ProCard loading={system.loading}>
            <Statistic title="运行主机" value={system.data?.hostname ?? '—'} />
          </ProCard>
        </Col>
        <Col xs={24} md={8}>
          <ProCard loading={interfaces.loading}>
            <Statistic
              title="网络接口"
              value={interfaces.data?.length ?? '—'}
            />
          </ProCard>
        </Col>
        <Col xs={24} md={8}>
          <ProCard loading={routes.loading}>
            <Statistic title="IPv4 路由" value={routes.data?.length ?? '—'} />
          </ProCard>
        </Col>
      </Row>
      <ProTable
        rowKey="name"
        headerTitle="接口状态"
        search={false}
        pagination={false}
        options={false}
        loading={interfaces.loading}
        dataSource={interfaces.data ?? []}
        scroll={{ x: 640 }}
        columns={[
          { title: '接口', dataIndex: 'name' },
          {
            title: '状态',
            key: 'status',
            render: (_, row) => (
              <Tag color={row.up && row.running ? 'success' : 'default'}>
                {row.up && row.running ? '运行中' : '未就绪'}
              </Tag>
            ),
          },
          { title: 'MTU', dataIndex: 'mtu' },
          {
            title: '地址',
            key: 'addresses',
            render: (_, row) =>
              row.addresses.map((a) => a.cidr).join('、') || '—',
          },
        ]}
      />
    </Page>
  );
}

export function Interfaces() {
  const state = useApi(api.interfaces, 5000);
  return (
    <Page title="网络接口" error={state.error} reload={state.reload}>
      <ProTable
        rowKey="name"
        search={false}
        options={false}
        loading={state.loading}
        dataSource={state.data ?? []}
        scroll={{ x: 960 }}
        pagination={{ pageSize: 10 }}
        columns={[
          { title: '接口', dataIndex: 'name' },
          { title: 'MAC 地址', dataIndex: 'mac' },
          {
            title: '状态',
            key: 'status',
            render: (_, r) => (
              <Tag color={r.up && r.running ? 'success' : 'default'}>
                {r.up && r.running ? '运行中' : '未就绪'}
              </Tag>
            ),
          },
          { title: 'MTU', dataIndex: 'mtu' },
          { title: '标志', key: 'flags', render: (_, r) => r.flags?.join('、') || '—' },
          {
            title: 'IP 地址',
            key: 'addresses',
            render: (_, r) => r.addresses.map((a) => a.cidr).join('、') || '—',
          },
        ]}
      />
    </Page>
  );
}

export function Routes() {
  const state = useApi(api.routes);
  return (
    <Page title="路由表" error={state.error} reload={state.reload}>
      <ProTable
        rowKey={(r) =>
          `${r.interface}-${r.destination}-${r.gateway}-${r.metric}`
        }
        search={false}
        options={false}
        loading={state.loading}
        dataSource={state.data ?? []}
        scroll={{ x: 760 }}
        columns={[
          { title: '目的网络', dataIndex: 'destination' },
          {
            title: '网关',
            dataIndex: 'gateway',
            renderText: (v) => (v === '0.0.0.0' ? '—' : v),
          },
          { title: '掩码', dataIndex: 'mask' },
          { title: '接口', dataIndex: 'interface' },
          { title: 'Metric', dataIndex: 'metric', valueType: 'digit' },
        ]}
      />
    </Page>
  );
}

export function Traffic() {
  const state = useApi(api.traffic, 3000);
  return (
    <Page title="流量统计" error={state.error} reload={state.reload}>
      <ProTable
        rowKey="interface"
        search={false}
        options={false}
        loading={state.loading}
        dataSource={state.data ?? []}
        scroll={{ x: 1080 }}
        columns={[
          { title: '接口', dataIndex: 'interface', fixed: 'left' },
          { title: '接收字节', dataIndex: 'rx_bytes', renderText: fmtBytes },
          { title: '发送字节', dataIndex: 'tx_bytes', renderText: fmtBytes },
          { title: '接收包', dataIndex: 'rx_packets', renderText: fmtInt },
          { title: '发送包', dataIndex: 'tx_packets', renderText: fmtInt },
          { title: '接收丢弃', dataIndex: 'rx_dropped', valueType: 'digit' },
          { title: '发送丢弃', dataIndex: 'tx_dropped', valueType: 'digit' },
          { title: '接收错误', dataIndex: 'rx_errors', valueType: 'digit' },
          { title: '发送错误', dataIndex: 'tx_errors', valueType: 'digit' },
        ]}
      />
    </Page>
  );
}

export function System() {
  const state = useApi(api.system);
  return (
    <Page title="系统信息" error={state.error} reload={state.reload}>
      <ProCard loading={state.loading}>
        <Descriptions
          bordered
          column={{ xs: 1, md: 2 }}
          items={[
            {
              key: 'hostname',
              label: '主机名',
              children: state.data?.hostname ?? '—',
            },
            { key: 'os', label: '操作系统', children: state.data?.os ?? '—' },
            {
              key: 'arch',
              label: '体系结构',
              children: state.data?.arch ?? '—',
            },
            {
              key: 'go',
              label: 'Go 版本',
              children: state.data?.go_version ?? '—',
            },
            { key: 'pid', label: '进程 ID', children: state.data?.pid ?? '—' },
          ]}
        />
      </ProCard>
    </Page>
  );
}
