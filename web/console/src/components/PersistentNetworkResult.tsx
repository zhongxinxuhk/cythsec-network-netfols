import { ProDescriptions, ProTable } from '@ant-design/pro-components';
import { Alert, Space, Tabs, Tag, Typography } from 'antd';
import type { PersistentField, PersistentNetworkInspection, PersistentNetworkProfile } from '@/api/network-config';

const statuses = { observed: '已取得来源快照', partial: '部分信息未取得', unavailable: '读取未完成', unsupported: '当前平台不支持' };
const scopes = { keyfile_profiles: 'NetworkManager keyfile', merged_ethernets: 'Netplan Ethernet 合并视图', committed_network: 'UCI 已提交配置' };
const warnings: Record<string, string> = {
  non_atomic_file_snapshot: '各源文件分次读取', runtime_and_adoption_not_verified: '运行归属与接管未核验', unsupported_platform: '当前主机不支持目标管理器配置读取',
  source_read_incomplete: '部分源文件不可读取或超出限制', legacy_ifcfg_and_plugins_not_inspected: 'ifcfg 与其他插件来源未读取', no_supported_source_files: '未发现可读取的受支持源文件',
  profile_schema_unsupported: '部分配置格式未兼容', conflicting_profile_references: '多个文件声明相同配置标识', workspace_unavailable: '私有读取目录不可用', native_read_unavailable: '原生工具、解析依赖或配置格式不可读取', version_identity_unavailable: '无法生成来源版本标识',
};
function fieldValue(profile: PersistentNetworkProfile, key: PersistentField) {
  if (profile.field_states[key] !== 'configured') return profile.field_states[key] === 'unset' ? '未显式配置' : '未解析';
  const value = profile[key];
  if (key === 'routes') return profile.routes?.length ?? '未取得';
  return Array.isArray(value) ? value.length ? value.join('；') : '显式空集合' : String(value);
}
export function PersistentNetworkResult({ report }: { report: PersistentNetworkInspection }) {
  return <div className="page-stack">
    <Alert showIcon type={report.status === 'observed' ? 'info' : 'warning'} title={`持久配置来源：${statuses[report.status]}`} />
    <ProDescriptions column={{ xs: 1, md: 2 }} dataSource={{}} columns={[
      { title: '读取范围', render: () => scopes[report.scope] }, { title: '平台', render: () => report.platform },
      { title: '读取时间', render: () => new Date(report.observed_at).toLocaleString() },
      { title: '快照标识', render: () => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{report.id}</Typography.Text> },
    ]} />
    <Tabs items={[
      { key: 'profiles', label: '配置声明', children: <ProTable<PersistentNetworkProfile> headerTitle="接口配置声明" rowKey={p => `${p.source_ids.join(':')}:${p.reference}`} dataSource={report.profiles} search={false} options={false} scroll={{ x: 1150 }} pagination={{ pageSize: 8, showSizeChanger: false }} locale={{ emptyText: report.status === 'observed' ? '已读取来源中无接口配置声明' : '未取得接口配置声明' }} columns={[
        { title: '配置标识', dataIndex: 'reference', width: 240 },
        { title: '设备声明', key: 'device', width: 140, render: (_, p) => p.device || '未核对' },
        { title: '来源归因', key: 'origin', width: 160, render: (_, p) => <Tag>{p.origin_verified ? '源文件已核对' : '合并来源待归因'}</Tag> },
        { title: '静态地址', key: 'addresses', width: 250, render: (_, p) => fieldValue(p, 'addresses') },
        { title: 'DNS 声明', key: 'dns', width: 230, render: (_, p) => fieldValue(p, 'dns') },
        { title: 'MTU', key: 'mtu', width: 140, render: (_, p) => fieldValue(p, 'mtu') },
      ]} expandable={{ expandedRowRender: p => <div className="page-stack">
        <ProDescriptions column={1} dataSource={{}} columns={[
          { title: '设备绑定', render: () => p.binding === 'declared' ? '配置中的字面设备名称' : '待解析匹配或重命名规则' },
          { title: '地址方式', render: () => Object.entries(p.methods).map(([key, value]) => `${key}=${value}`).join('；') || '未显式配置' },
          { title: '搜索域', render: () => fieldValue(p, 'search') },
          { title: '源文件', render: () => p.source_ids.map(id => report.sources.find(s => s.id === id)?.path).join('；') },
        ]} />
        {p.field_states.routes === 'configured' ? <ProTable<NonNullable<PersistentNetworkProfile['routes']>[number]> headerTitle="静态路由声明" rowKey={(_, index) => String(index)} dataSource={p.routes ?? []} search={false} options={false} pagination={false} scroll={{ x: 650 }} columns={[
          { title: '目标网络', dataIndex: 'destination' }, { title: '下一跳', dataIndex: 'gateway' }, { title: 'Metric', key: 'metric', render: (_, r) => r.metric === null ? '未显式配置' : r.metric },
        ]} /> : <Typography.Text type="secondary">路由：{fieldValue(p, 'routes')}</Typography.Text>}
      </div> }} /> },
      { key: 'sources', label: '来源证据', children: <ProTable<PersistentNetworkInspection['sources'][number]> headerTitle="源文件快照" rowKey="id" dataSource={report.sources} search={false} options={false} scroll={{ x: 1050 }} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: '未取得配置来源' }} columns={[
        { title: '配置文件', dataIndex: 'path', width: 390 },
        { title: '存储类别', key: 'storage', width: 120, render: (_, s) => ({ persistent: '持久文件', runtime: '临时文件', vendor: '厂商文件' }[s.storage]) },
        { title: '读取状态', key: 'state', width: 140, render: (_, s) => ({ read: '已读取', unavailable: '不可读取', unsupported: '格式未兼容' }[s.state]) },
        { title: '文件大小', key: 'bytes', width: 100, render: (_, s) => s.state === 'unavailable' ? '未取得' : `${s.bytes} B` },
        { title: '版本标识', key: 'version', width: 300, render: (_, s) => s.version_tag ? <Typography.Text copyable={{ text: s.version_tag }}>{s.version_tag.slice(0, 16)}…</Typography.Text> : '未取得' },
      ]} /> },
    ]} />
    <Space wrap>{report.warnings.map(code => <Tag key={code}>{warnings[code] ?? '来源信息待核对'}</Tag>)}</Space>
  </div>;
}
