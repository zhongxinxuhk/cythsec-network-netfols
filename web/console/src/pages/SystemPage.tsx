import { PageContainer, ProDescriptions } from '@ant-design/pro-components';
import { Alert, Button } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { api } from '@/api/client';
import { useApi } from '@/hooks/useApi';
export function SystemPage() {
  const { data, loading, error, reload } = useApi(api.system);
  return <PageContainer content="routerd 运行所在主机与进程信息。" extra={<Button icon={<ReloadOutlined />} onClick={reload} loading={loading}>刷新</Button>}>
    {error ? <Alert type="error" title={error} role="alert" showIcon /> : <ProDescriptions title="系统信息" bordered column={{ xs: 1, sm: 2 }} loading={loading} dataSource={data ?? {}} columns={[
      { title: '主机名 hostname', dataIndex: 'hostname' },
      { title: '操作系统 os', dataIndex: 'os' },
      { title: '处理器架构', dataIndex: 'arch' },
      { title: 'Go 版本', dataIndex: 'go_version' },
      { title: '进程 pid', dataIndex: 'pid' },
    ]} />}
  </PageContainer>;
}
export default SystemPage;
