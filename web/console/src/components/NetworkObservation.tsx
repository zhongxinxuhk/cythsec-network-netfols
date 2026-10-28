import { ProDescriptions, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Collapse, Empty, Space, Tabs, Tag, Typography } from 'antd';
import type { NetworkFieldDifference, NetworkCheckIssue, NetworkObservation, NetworkPreflight, ObservedNetworkInterface, NetworkNativeValidation } from '@/api/network-config';
const managerNames: Record<string, string> = { networkmanager: 'NetworkManager', netplan: 'Netplan/networkd', networkd: 'systemd-networkd', openwrt: 'OpenWrt/netifd' };
const managerStates: Record<string, string> = { active: '可读取', inactive: '未运行', partial: '读取不完整', unavailable: '不可读取', unsupported: '不适用' };
const kinds: Record<string, string> = { physical_ethernet: '物理以太网', bridge: '桥接口', bond: 'Bond', vlan: 'VLAN', master_member: '组合接口成员', wireless: '无线', tunnel: '隧道', loopback: '回环', virtual_or_unknown: '虚拟/待核对', unknown: '未知' };
const fields: Record<string, string> = { mtu: 'MTU（字节）', addresses: '运行地址（含自动地址）', dns: '链路DNS', search: '搜索域', routes: '主路由表运行值' };
const valueLabel = (value: number | string[] | null) => value === null ? '未取得' : Array.isArray(value) ? value.length ? value.join('；') : '空集合' : String(value);
export function NetworkEnvironmentPanel({ observation, error, loading, onRefresh }: { observation: NetworkObservation | null; error: string; loading: boolean; onRefresh: () => void }) {
  const columns: ProColumns<ObservedNetworkInterface>[] = [
    { title: '接口', dataIndex: 'device', width: 120 },
    { title: '类型', dataIndex: 'kind', width: 140, render: (_, p) => kinds[p.kind] ?? '未知' },
    { title: '管理归属', key: 'owners', width: 260, render: (_, p) => p.owners.length ? <Space wrap>{p.owners.map((owner, i) => <Tag key={i} color={p.owners.length > 1 ? 'error' : 'default'}>{managerNames[owner.backend] ?? owner.backend}{owner.reference ? ` · ${owner.reference}` : ''}</Tag>)}</Space> : '未知' },
    { title: 'MTU', key: 'mtu', width: 90, render: (_, p) => p.known.mtu ? p.mtu ?? '未取得' : '未取得' },
    { title: '运行地址', key: 'addresses', width: 320, render: (_, p) => p.known.addresses ? valueLabel(p.addresses) : '未取得' },
    { title: 'DNS', key: 'dns', width: 240, render: (_, p) => p.known.dns ? valueLabel(p.dns) : '未取得' },
  ];
  return <Collapse items={[{ key: 'environment', label: '网络环境与接口归属', children: <div className="page-stack">
    <Space wrap><Button loading={loading} onClick={onRefresh}>读取环境</Button>{observation && <Typography.Text type="secondary">最近读取：{new Date(observation.observed_at).toLocaleString()}</Typography.Text>}</Space>
    {error && <Alert type="error" title={error} showIcon role="alert" />}
    {!observation && !error && !loading && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未读取网络环境" />}
    {observation && <>
      <ProDescriptions column={{ xs: 1, md: 3 }} dataSource={{}} columns={[
        { title: '平台', render: () => observation.platform },
        { title: '读取状态', render: () => <Tag>{observation.status === 'observed' ? '已取得快照' : '部分信息未取得'}</Tag> },
        { title: '快照范围', render: () => '运行态（非事务快照）' },
      ]} />
      <ProTable<NetworkObservation['managers'][number]> headerTitle="管理器状态" rowKey="backend" dataSource={observation.managers} search={false} options={false} pagination={false} scroll={{ x: 600 }} columns={[
        { title: '管理器', dataIndex: 'backend', render: (_, m) => managerNames[m.backend] ?? m.backend },
        { title: '状态', dataIndex: 'state', render: (_, m) => managerStates[m.state] ?? '未知' },
        { title: '工具版本', dataIndex: 'tool_version', render: (_, m) => m.tool_version || '未提供' },
        { title: '诊断', dataIndex: 'diagnostic', render: (_, m) => ({ probe_unavailable: '工具或服务不可读取', unsupported_schema: '读取格式未兼容', unsupported_platform: '当前平台不适用', inactive: '服务未运行', failed: '服务报告失败', unknown: '服务状态未知' }[m.diagnostic] ?? m.diagnostic) || '—' },
      ]} />
      <ProTable<ObservedNetworkInterface> headerTitle={observation.inventory_available ? `接口快照 · ${observation.interfaces.length} 项` : '接口快照不可用'} rowKey="device" columns={columns} dataSource={observation.interfaces} search={false} options={false} pagination={{ pageSize: 10, showSizeChanger: false }} scroll={{ x: 1170 }} locale={{ emptyText: observation.inventory_available ? '未发现接口' : '接口列表不可用' }} />
    </>}
  </div> }]} />;
}
export function NetworkPreflightResult({ report }: { report: NetworkPreflight }) {
  const differences: ProColumns<NetworkFieldDifference>[] = [
    { title: '接口', dataIndex: 'device', width: 110 },
    { title: '字段', dataIndex: 'field', width: 210, render: (_, d) => fields[d.field] ?? d.field },
    { title: '当前运行值', key: 'current', width: 300, render: (_, d) => <Typography.Paragraph ellipsis={{ rows: 2, expandable: true }}>{d.state === 'unknown' ? '未取得' : valueLabel(d.current)}</Typography.Paragraph> },
    { title: '草稿值', key: 'desired', width: 300, render: (_, d) => <Typography.Paragraph ellipsis={{ rows: 2, expandable: true }}>{valueLabel(d.desired)}</Typography.Paragraph> },
    { title: '比较', key: 'state', width: 100, render: (_, d) => <Tag color={d.state === 'different' ? 'warning' : 'default'}>{{ same: '相同', different: '不同', unknown: '未知' }[d.state]}</Tag> },
    { title: '来源', dataIndex: 'source', width: 180 },
  ];
  return <div className="page-stack">
    <Alert showIcon type={report.status === 'blocked' ? 'error' : 'warning'} title={report.status === 'blocked' ? '存在接管阻断项' : '仍有应用条件待核对'} description="比较基于本次运行态快照，不作为系统应用确认。" />
    <ProDescriptions column={1} dataSource={{}} columns={[
      { title: '快照时间', render: () => new Date(report.observation.observed_at).toLocaleString() },
      { title: '草稿摘要', render: () => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{report.draft_digest}</Typography.Text> },
      { title: '快照标识', render: () => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{report.observation.id}</Typography.Text> },
    ]} />
    <Tabs items={[
      { key: 'checks', label: '检查项', children: <ProTable<NetworkCheckIssue> headerTitle="应用条件" rowKey={issue => `${issue.device}:${issue.code}`} dataSource={report.issues} search={false} options={false} pagination={false} scroll={{ x: 650 }} columns={[
        { title: '级别', dataIndex: 'severity', width: 100, render: (_, issue) => <Tag color={issue.severity === 'blocker' ? 'error' : 'warning'}>{issue.severity === 'blocker' ? '阻断' : '待核对'}</Tag> },
        { title: '接口', dataIndex: 'device', width: 120, render: (_, issue) => issue.device || '全局' },
        { title: '说明', dataIndex: 'message' },
      ]} /> },
      { key: 'differences', label: '运行态差异', children: <ProTable<NetworkFieldDifference> headerTitle="运行值与静态草稿比较" rowKey={d => `${d.device}:${d.field}`} columns={differences} dataSource={report.differences} search={false} options={false} pagination={{ pageSize: 10, showSizeChanger: false }} scroll={{ x: 1200 }} /> },
    ]} />
  </div>;
}

export function NetworkNativeValidationResult({ report }: { report: NetworkNativeValidation }) {
  const states = { passed: '通过', rejected: '配置被拒绝', unavailable: '未完成', unsupported: '不支持' };
  return <div className="page-stack">
    <Alert showIcon type={report.status === 'passed' ? 'success' : report.status === 'rejected' ? 'error' : 'warning'} title={`原生解析校验：${states[report.status]}`} />
    <ProDescriptions column={{ xs: 1, md: 2 }} dataSource={{}} columns={[
      { title: '目标管理器', render: () => managerNames[report.backend] },
      { title: '平台', render: () => report.platform },
      { title: '校验范围', render: () => report.scope === 'offline_profile' ? '离线连接配置解析' : '配置语法解析' },
      { title: '工具版本', render: () => report.tool_version || '未提供' },
      { title: '校验时间', render: () => new Date(report.checked_at).toLocaleString() },
      { title: '配置摘要', render: () => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{report.draft_digest}</Typography.Text> },
    ]} />
    <ProTable<NetworkNativeValidation['checks'][number]> headerTitle="配置文件检查" rowKey="artifact" dataSource={report.checks} search={false} options={false} pagination={false} scroll={{ x: 720 }} columns={[
      { title: '配置文件', dataIndex: 'artifact', width: 240 },
      { title: '结果', dataIndex: 'state', width: 120, render: (_, c) => <Tag color={c.state === 'passed' ? 'success' : c.state === 'rejected' ? 'error' : 'warning'}>{states[c.state]}</Tag> },
      { title: '说明', dataIndex: 'message' },
    ]} />
  </div>;
}
