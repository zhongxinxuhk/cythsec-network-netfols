import { ProDescriptions, ProTable } from '@ant-design/pro-components';
import { Alert, Empty, Space, Tabs, Tag, Typography } from 'antd';
import type { PersistentField, PersistentNetworkInspection, PersistentNetworkProfile } from '@/api/network-config';

const statuses = { observed: '已取得来源快照', partial: '部分信息未取得', unavailable: '读取未完成', unsupported: '当前平台不支持' };
const scopes = { keyfile_profiles: 'NetworkManager keyfile', merged_ethernets: 'Netplan Ethernet 合并视图', committed_network: 'UCI 已提交配置' };
const associationStates = { active: '当前配置已激活', inactive: '设备未激活', transitioning: '设备状态转换中', unmanaged: 'NM 未管理', unavailable_device: '设备暂不可用', not_observed: '当前身份未观察到设备', conflicting: '设备正在使用其他配置', unknown: '未知' };
const evidenceStates = { observed: '已取得关联快照', inactive: '服务未运行', unavailable: '不可读取', unsupported: '当前平台不支持', not_checked: '当前适配器未提供' };
const loadedStates = { partial: '基础字段已比较', different: '存在加载差异', unavailable: '加载字段不可读取', unsupported: '当前平台不支持', not_checked: '尚未比较' };
const loadedLabels = { device: '设备名称', mtu: 'MTU 声明', ipv4_method: 'IPv4 地址方式', ipv6_method: 'IPv6 地址方式', addresses: '静态地址集合', dns: 'DNS 地址集合', search: '搜索域集合' };
const loadedReasons: Record<string, string> = { compared: '已比较', source_unset_or_unsupported: '来源未显式配置或格式未解析', loaded_field_unsupported: '加载字段格式未解析' };
const loadedDiagnostics: Record<string, string> = { reference_not_matched: '加载引用未匹配', unsupported_platform: '当前平台不支持', backend_not_supported: '当前适配器未提供', settings_unavailable: '查询未完成，请核对工具与读取权限', settings_schema_unsupported: '加载响应格式未兼容', profile_not_observed: '当前身份未观察到该配置', partial_scope_not_full_sync: '标量与集合成员比较' };
function loadedValue(value: number | string | string[] | null, field: string) {
  if (value === null) return '未核验';
  if (field === 'mtu' && value === 0) return '自动';
  return Array.isArray(value) ? value.length ? value.join('；') : '空集合' : String(value);
}
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
      { key: 'profiles', label: '配置声明', children: <ProTable<PersistentNetworkProfile> headerTitle="接口配置声明" rowKey={p => `${p.source_ids.join(':')}:${p.reference}`} dataSource={report.profiles} search={false} options={false} scroll={{ x: 1310 }} pagination={{ pageSize: 8, showSizeChanger: false }} locale={{ emptyText: report.status === 'observed' ? '已读取来源中无接口配置声明' : '未取得接口配置声明' }} columns={[
        { title: '配置标识', dataIndex: 'reference', width: 240 },
        { title: '设备声明', key: 'device', width: 140, render: (_, p) => p.device || '未核对' },
        { title: '加载引用', key: 'loaded', width: 150, render: (_, p) => ({ matched: '引用匹配', not_observed: '当前身份未观察到', conflicting: '引用冲突', unknown: '未核验' }[p.load_reference ?? 'unknown']) },
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
        {p.field_states.routes === 'configured' ? <ProTable<NonNullable<PersistentNetworkProfile['routes']>[number] & { row_id: string }> headerTitle="静态路由声明" rowKey="row_id" dataSource={(p.routes ?? []).map((route, index) => ({ ...route, row_id: `${index}:${route.destination}:${route.gateway}` }))} search={false} options={false} pagination={false} scroll={{ x: 650 }} columns={[
          { title: '目标网络', dataIndex: 'destination' }, { title: '下一跳', dataIndex: 'gateway' }, { title: 'Metric', key: 'metric', render: (_, r) => r.metric === null ? '未显式配置' : r.metric },
        ]} /> : <Typography.Text type="secondary">路由：{fieldValue(p, 'routes')}</Typography.Text>}
      </div> }} /> },
      { key: 'devices', label: '设备关联', children: <div className="page-stack">
        <ProDescriptions column={{ xs: 1, md: 2 }} dataSource={{}} columns={[
          { title: '关联查询', render: () => report.device_evidence ? evidenceStates[report.device_evidence.state] : '未取得' },
          { title: '观察范围', render: () => '当前服务身份可见的 NetworkManager 设备' },
          { title: '关联观察时间', render: () => report.device_evidence ? new Date(report.device_evidence.observed_at).toLocaleString() : '未取得' },
        ]} />
        <ProTable<PersistentNetworkProfile> headerTitle="配置与设备关联" rowKey={p => `${p.source_ids.join(':')}:${p.reference}`} dataSource={report.profiles} search={false} options={false} pagination={{ pageSize: 8, showSizeChanger: false }} scroll={{ x: 1100 }} locale={{ emptyText: '未取得可核对的配置声明' }} columns={[
          { title: '配置标识', dataIndex: 'reference', width: 260 },
          { title: '设备声明', key: 'device', width: 140, render: (_, p) => p.device || '未核对' },
          { title: '关联状态', key: 'state', width: 220, render: (_, p) => <Tag color={p.device_association?.state === 'conflicting' || p.device_association?.state === 'unmanaged' ? 'error' : 'default'}>{associationStates[p.device_association?.state ?? 'unknown']}</Tag> },
          { title: 'NM 设备状态码', key: 'code', width: 150, render: (_, p) => p.device_association?.device_state ?? '未知' },
          { title: 'NM 受管', key: 'managed', width: 120, render: (_, p) => p.device_association?.managed === true ? '是' : p.device_association?.managed === false ? '否' : '未知' },
          { title: '活动配置 UUID 匹配', key: 'match', width: 190, render: (_, p) => p.device_association?.active_profile_matches === true ? '匹配' : p.device_association?.active_profile_matches === false ? '不匹配' : '未知' },
        ]} />
      </div> },
      { key: 'loaded', label: '加载差异', children: <ProTable<PersistentNetworkProfile> headerTitle="源文件与加载配置比较" rowKey={p => `${p.source_ids.join(':')}:${p.reference}`} dataSource={report.profiles} search={false} options={false} pagination={{ pageSize: 8, showSizeChanger: false }} scroll={{ x: 1100 }} locale={{ emptyText: report.platform === 'linux' ? '未取得可比较的配置声明' : '当前平台不支持加载配置比较' }} columns={[
        { title: '配置标识', dataIndex: 'reference', width: 260 },
        { title: '比较状态', key: 'state', width: 200, render: (_, p) => <Tag color={p.loaded_comparison?.state === 'different' ? 'error' : 'default'}>{p.loaded_comparison ? loadedStates[p.loaded_comparison.state] : '未取得'}</Tag> },
        { title: '检查时间', key: 'time', width: 200, render: (_, p) => p.loaded_comparison ? new Date(p.loaded_comparison.observed_at).toLocaleString() : '未取得' },
        { title: '检查说明', key: 'diagnostic', width: 300, render: (_, p) => p.loaded_comparison ? loadedDiagnostics[p.loaded_comparison.diagnostic] ?? '待核验' : '未取得' },
      ]} expandable={{ rowExpandable: p => Boolean(p.loaded_comparison?.fields.length), expandedRowRender: p => <ProTable<NonNullable<PersistentNetworkProfile['loaded_comparison']>['fields'][number]> rowKey="field" headerTitle="基础字段与集合成员" dataSource={p.loaded_comparison?.fields} search={false} options={false} pagination={false} scroll={{ x: 1100 }} columns={[
        { title: '字段', key: 'field', width: 160, render: (_, f) => loadedLabels[f.field] },
        { title: '源文件声明', key: 'source', width: 260, render: (_, f) => loadedValue(f.source, f.field) },
        { title: '管理器加载值', key: 'loaded', width: 260, render: (_, f) => loadedValue(f.loaded, f.field) },
        { title: '比较结果', key: 'state', width: 130, render: (_, f) => <Tag color={f.state === 'different' ? 'error' : 'default'}>{{ same: '一致', different: '不同', unknown: '未核验' }[f.state]}</Tag> },
        { title: '依据', key: 'reason', width: 250, render: (_, f) => loadedReasons[f.reason] ?? '未核验' },
      ]} /> }} /> },
      { key: 'sources', label: '来源证据', children: <ProTable<PersistentNetworkInspection['sources'][number]> headerTitle="源文件快照" rowKey="id" dataSource={report.sources} search={false} options={false} scroll={{ x: 1500 }} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: '未取得配置来源' }} columns={[
        { title: '配置文件', dataIndex: 'path', width: 390 },
        { title: '存储类别', key: 'storage', width: 120, render: (_, s) => ({ persistent: '持久文件', runtime: '临时文件', vendor: '厂商文件' }[s.storage]) },
        { title: '读取状态', key: 'state', width: 140, render: (_, s) => ({ read: '已读取', unavailable: '不可读取', unsupported: '格式未兼容' }[s.state]) },
        { title: '所有者 UID / GID', key: 'owner', width: 160, render: (_, s) => `${s.safety?.uid ?? '未知'} / ${s.safety?.gid ?? '未知'}` },
        { title: '权限 / 稳定性', key: 'mode', width: 170, render: (_, s) => <Space orientation="vertical"><Typography.Text>{s.safety?.mode || '未取得'}</Typography.Text><Tag>{s.safety?.stable === true ? '本次捕获一致' : s.safety?.stable === false ? '捕获期间发生变化' : '一致性未核验'}</Tag></Space> },
        { title: '权限基线', key: 'safety', width: 140, render: (_, s) => <Tag color={s.safety?.status === 'blocked' ? 'error' : 'default'}>{{ meets_baseline: '符合基线', review: '需复核', blocked: '不符合基线', unknown: '未知' }[s.safety?.status ?? 'unknown']}</Tag> },
        { title: '文件大小', key: 'bytes', width: 100, render: (_, s) => s.state === 'unavailable' ? '未取得' : `${s.bytes} B` },
        { title: '版本标识', key: 'version', width: 300, render: (_, s) => s.version_tag ? <Typography.Text copyable={{ text: s.version_tag }}>{s.version_tag.slice(0, 16)}…</Typography.Text> : '未取得' },
      ]} /> },
      { key: 'authority', label: '接管条件', children: report.authority ? <div className="page-stack">
        <Alert showIcon type={report.authority.status === 'blocked' ? 'error' : 'warning'} title={report.authority.status === 'blocked' ? '存在接管阻断项' : '接管条件待复核'} />
        <ProDescriptions column={{ xs: 1, md: 2 }} dataSource={{}} columns={[
          { title: '管理器引用查询', render: () => ({ observed: '已取得可见引用', inactive: '服务未运行', unavailable: '不可读取', unsupported: '当前平台不支持', not_checked: '当前适配器未提供' }[report.manager?.state ?? 'not_checked']) },
          { title: '引用范围', render: () => '当前服务身份可见的配置引用' },
          { title: '查询时间', render: () => report.manager ? new Date(report.manager.observed_at).toLocaleString() : '未取得' },
          { title: '完整内容同步', render: () => '待核验' },
        ]} />
        <ProTable<NonNullable<PersistentNetworkInspection['authority']>['issues'][number]> headerTitle="接管检查项" rowKey={issue => `${issue.source_id}:${issue.reference}:${issue.severity}:${issue.code}`} dataSource={report.authority.issues} search={false} options={false} pagination={{ pageSize: 8, showSizeChanger: false }} scroll={{ x: 850 }} columns={[
          { title: '级别', key: 'severity', width: 100, render: (_, i) => <Tag color={i.severity === 'blocker' ? 'error' : 'warning'}>{i.severity === 'blocker' ? '阻断' : '待复核'}</Tag> },
          { title: '配置标识', dataIndex: 'reference', width: 230, render: (_, i) => i.reference || '全局' },
          { title: '来源', key: 'source', width: 250, render: (_, i) => report.sources.find(s => s.id === i.source_id)?.path || '—' },
          { title: '检查说明', dataIndex: 'message', width: 360 },
        ]} />
      </div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="接管条件未取得" /> },
    ]} />
    <Space wrap>{report.warnings.map(code => <Tag key={code}>{warnings[code] ?? '来源信息待核对'}</Tag>)}</Space>
  </div>;
}
