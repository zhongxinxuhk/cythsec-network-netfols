import { Fragment, useState, useSyncExternalStore, type ReactNode } from 'react';
import { Alert, Button, Drawer, Form, Input, Modal, Space, Tag } from 'antd';
import { LockOutlined, LogoutOutlined } from '@ant-design/icons';
import { accessRevision, ApiError, connect, disconnect, serviceAccess, subscribeAccess, type Service } from '@/api/http';
import { useApi } from '@/hooks/useApi';

// Replacing credentials resets all page data. Late responses are also rejected by secureFetch.
export function AccessBoundary({ children }: { children: ReactNode }) {
  const revision = useSyncExternalStore(subscribeAccess, accessRevision);
  return <Fragment key={revision}>{children}</Fragment>;
}
function ServiceConnection({ service, label }: { service: Service; label: string }) {
  const access = useApi(() => serviceAccess(service), 10000);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [form] = Form.useForm<{ credential: string }>();
  const required = access.error && !access.data;
  return <Space wrap>
    {access.data?.enabled ? <>
      <Tag>{label} · {access.data.name} · {{ viewer: '只读', operator: '运维', admin: '管理员' }[access.data.role || 'viewer']}</Tag>
      <Button size="small" icon={<LogoutOutlined />} onClick={() => disconnect(service)}>断开{label}</Button>
    </> : <Button size="small" icon={<LockOutlined />} onClick={() => { setError(''); setOpen(true); }}>
      {label} · {access.loading ? '检查中' : access.data ? '鉴权未启用' : '连接认证'}
    </Button>}
    <Modal title={`${label}访问认证`} open={open} footer={null} destroyOnHidden onCancel={() => setOpen(false)} afterClose={() => form.resetFields()}>
      <Space orientation="vertical" style={{ width: '100%' }}>
        <Alert type={access.data ? 'warning' : 'info'} title={access.data ? '该服务未启用鉴权，本界面不代表已登录' : '使用管理员配置的服务凭据，凭据仅保留在当前页面内存，刷新后需要重新连接。'} />
        {required && <Alert type="warning" title={access.error} />}
        {error && <Alert type="error" title={error} role="alert" />}
        {!access.data && <Form form={form} layout="vertical" onFinish={async ({ credential }) => {
          setBusy(true); setError('');
          try { await connect(service, credential); form.resetFields(); }
          catch (e) { setError(e instanceof ApiError ? e.message : '无法完成服务认证，请检查服务连接'); }
          finally { setBusy(false); }
        }}>
          <Form.Item name="credential" label="访问凭据" rules={[{ required: true, min: 32, max: 256, message: '请输入 32～256 字符访问凭据' }]}>
            <Input.Password autoComplete="off" maxLength={256} />
          </Form.Item>
          <Button htmlType="submit" type="primary" loading={busy}>连接服务</Button>
        </Form>}
      </Space>
    </Modal>
  </Space>;
}
export function ServiceAccess() {
  const [open, setOpen] = useState(false);
  return <>
    <Button size="small" icon={<LockOutlined />} onClick={() => setOpen(true)}>访问认证</Button>
    <Drawer title="管理服务访问" open={open} onClose={() => setOpen(false)} destroyOnHidden>
      <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <ServiceConnection service="routerd" label="控制面" />
        <ServiceConnection service="telemetryd" label="聚合服务" />
        <Alert type="info" title="两个服务分别认证。刷新页面或断开连接后，凭据从当前页面内存移除。" />
      </Space>
    </Drawer>
  </>;
}
