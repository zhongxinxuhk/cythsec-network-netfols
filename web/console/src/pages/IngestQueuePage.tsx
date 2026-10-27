import { Link } from '@umijs/max';
import { PageContainer, ProCard, ProDescriptions } from '@ant-design/pro-components';
import { ReloadOutlined } from '@ant-design/icons';
import { Button, Collapse, Space, Typography } from 'antd';
import { IngestPanel } from '@/components/IngestPanel';
import { useIngestStatus } from '@/hooks/useIngestStatus';

export default function IngestQueuePage() {
  const { status, error, loading, updatedAt, reload } = useIngestStatus();
  return <PageContainer content="待写容量、消费者状态与历史确认" extra={[
    <Button aria-label="刷新状态" key="reload" icon={<ReloadOutlined />} loading={loading} onClick={reload}>刷新状态</Button>,
  ]}><div className="page-stack">
    <ProCard variant="outlined">
      <Space wrap size="large">
        <Typography.Text>最近成功读取：{updatedAt ? new Date(updatedAt).toLocaleString() : '尚未成功读取'}</Typography.Text>
        <Typography.Text type="secondary">每3秒刷新</Typography.Text>
        <Link to="/analytics">查看聚合历史</Link>
      </Space>
    </ProCard>
    <IngestPanel status={status} error={error} />
    <ProCard title="确认阶段与处理规则" variant="outlined">
      <ProDescriptions column={1} dataSource={{}} columns={[
        { title: '队列确认', render: () => '待写数据已落盘，尚未确认写入历史。' },
        { title: '历史确认', render: () => '以聚合历史查询返回的批次为准。' },
        { title: '进程计数', render: () => '完成、去重、失败次数随当前消费者进程重启归零。' },
      ]} />
      <Collapse items={[
        { key: 'capacity', label: '容量与退避处理', children: <Typography.Paragraph>容量满时保留发送端输入。检查历史存储容量和服务日志；退避期间保留待写批次，按下次重试时间观察结果。</Typography.Paragraph> },
        { key: 'blocked', label: '校验与确认异常', children: <Typography.Paragraph>需要重启校验时，先核查队列与历史存储错误并保留待写文件。历史已保存而队列确认失败时，通过相同内容标识核对历史，避免重复提交不同输入。</Typography.Paragraph> },
      ]} />
    </ProCard>
  </div></PageContainer>;
}
