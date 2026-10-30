import { useEffect, useRef, useState } from 'react';
import { PageContainer, ProCard, ProDescriptions } from '@ant-design/pro-components';
import { Alert, AutoComplete, Button, Col, Drawer, Empty, Form, Input, InputNumber, Popconfirm, Row, Select, Space, Tabs, Tag, Tooltip, Typography } from 'antd';
import { DeleteOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { api } from '@/api/client';
import { ApiError } from '@/api/http';
import { networkConfig, type NetworkDraft, type NetworkPreview, type NetworkObservation, type NetworkPreflight, type NetworkNativeValidation, type PersistentNetworkInspection } from '@/api/network-config';
import { NetworkEnvironmentPanel, NetworkPreflightResult, NetworkNativeValidationResult } from '@/components/NetworkObservation';
import { PersistentNetworkResult } from '@/components/PersistentNetworkResult';
import { useApi } from '@/hooks/useApi';

const managers = [
  { value: 'netplan', label: 'Netplan / networkd（Ubuntu Server）' },
  { value: 'networkmanager', label: 'NetworkManager（Rocky / 麒麟 V11）' },
  { value: 'openwrt', label: 'UCI / netifd（OpenWrt）' },
];
export default function NetworkConfigurationPage() {
  const state = useApi(networkConfig.read);
  const inventory = useApi(api.interfaces);
  const [form] = Form.useForm<NetworkDraft>();
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [conflict, setConflict] = useState(false);
  const [preview, setPreview] = useState<NetworkPreview | null>(null);
  const [environment, setEnvironment] = useState<NetworkObservation | null>(null);
  const [environmentError, setEnvironmentError] = useState('');
  const [report, setReport] = useState<NetworkPreflight | null>(null);
  const [nativeValidation, setNativeValidation] = useState<NetworkNativeValidation | null>(null);
  const [persistent, setPersistent] = useState<PersistentNetworkInspection | null>(null);
  const inspectionRequest = useRef(0);
  const generation = useRef(0);
  useEffect(() => {
    if (state.data) { form.setFieldsValue(state.data.snapshot.config); setRevision(state.data.snapshot.revision); setConflict(false); setError(''); setNotice(''); setPreview(null); setReport(null); setNativeValidation(null); setPersistent(null); generation.current++; }
  }, [state.data, form]);
  async function submit(mode: 'save' | 'preview' | 'preflight' | 'native') {
    let draft: NetworkDraft;
    try { draft = await form.validateFields(); } catch { return; }
    setBusy(true); setError(''); setNotice('');
    if (mode === 'native') setNativeValidation(null);
    const epoch = generation.current;
    try {
      if (mode === 'save') {
        const result = await networkConfig.save(draft, revision);
        if (epoch === generation.current) { setRevision(result.revision); setNotice(`草稿已保存 · 版本 ${result.revision}`); }
      } else if (mode === 'preflight') {
        const result = await networkConfig.preflight(draft);
        if (epoch === generation.current) { setReport(result); setEnvironment(result.observation); setEnvironmentError(''); }
      } else if (mode === 'native') {
        const result = await networkConfig.validateNative(draft);
        if (epoch === generation.current) setNativeValidation(result);
      } else {
        const result = await networkConfig.preview(draft);
        if (epoch === generation.current) setPreview(result);
      }
    } catch (cause) {
      if (epoch === generation.current) {
        const changed = cause instanceof ApiError && cause.status === 412;
        setConflict(changed);
        setError(changed ? '服务端配置版本已变化，当前编辑已保留。请重新读取后比较。' : cause instanceof Error ? cause.message : '配置请求失败');
      }
    } finally { setBusy(false); }
  }
  async function readEnvironment() {
    setBusy(true); setEnvironmentError(''); setReport(null);
    try { setEnvironment(await networkConfig.observe()); }
    catch (cause) { setEnvironment(null); setEnvironmentError(cause instanceof Error ? cause.message : '环境读取失败'); }
    finally { setBusy(false); }
  }
  async function inspectPersistent() {
    const backend: NetworkDraft['backend'] = form.getFieldValue('backend');
    const ticket = ++inspectionRequest.current;
    const epoch = generation.current;
    setBusy(true); setError(''); setPersistent(null);
    try {
      const result = await networkConfig.inspectPersistent(backend);
      if (ticket === inspectionRequest.current && epoch === generation.current) setPersistent(result);
    } catch (cause) {
      if (ticket === inspectionRequest.current && epoch === generation.current) setError(cause instanceof Error ? cause.message : '持久配置读取失败');
    } finally { if (ticket === inspectionRequest.current) setBusy(false); }
  }
  const ready = Boolean(state.data && !state.error && !state.loading);
  return <PageContainer content="接口静态地址、DNS 与静态路由" extra={[
    <Popconfirm key="reload" title="重新读取将替换未保存的编辑内容" onConfirm={state.reload} disabled={busy}><Button icon={<ReloadOutlined />} disabled={busy} loading={state.loading}>重新读取</Button></Popconfirm>,
  ]}><div className="page-stack">
    {state.error && <Alert type="error" title={`网络配置不可用：${state.error}`} showIcon />}
    {error && <Alert type="error" title={error} showIcon role="alert" />}
    {notice && <Alert type="success" title={notice} showIcon role="status" />}
    {state.data && <ProCard variant="outlined"><ProDescriptions column={{ xs: 1, md: 3 }} dataSource={{}} columns={[
      { title: '草稿版本', render: () => revision ? `v${revision}` : '尚未保存' },
      { title: '系统应用', render: () => <Tag>未发布</Tag> },
      { title: '保存权限', render: () => state.data?.capabilities.can_save ? '管理员' : '当前连接不可保存' },
    ]} /></ProCard>}
    {state.data?.capabilities.can_observe && <NetworkEnvironmentPanel observation={environment} error={environmentError} loading={busy} onRefresh={() => void readEnvironment()} />}
    {state.data && <Form className="page-stack" form={form} layout="vertical" disabled={busy || !ready} onValuesChange={() => { generation.current++; setPreview(null); setReport(null); setNativeValidation(null); setPersistent(null); setNotice(''); }}>
      <ProCard title="目标管理器" variant="outlined" extra={state.data?.capabilities.can_inspect_persistent && <Button disabled={!ready} loading={busy} onClick={() => void inspectPersistent()}>读取持久配置</Button>}>
        <Form.Item name="backend" label="网络管理器" rules={[{ required: true }]}><Select options={managers} /></Form.Item>
      </ProCard>
      <Form.List name="interfaces" rules={[{ validator: async (_, value) => { if (!value?.length || value.length > 32) throw new Error('请配置1至32个接口'); } }]}>
        {(fields, { add, remove }, { errors }) => <div className="page-stack">
          {!fields.length && <ProCard variant="outlined"><Empty description="尚无接口配置" /></ProCard>}
          {fields.map(field => <ProCard key={field.key} title={`接口配置 ${field.name + 1}`} variant="outlined" extra={<Button danger type="text" icon={<DeleteOutlined />} onClick={() => remove(field.name)}>删除接口</Button>}>
            <Row gutter={16}>
              <Col xs={24} md={8}><Form.Item name={[field.name, 'id']} label="配置标识" rules={[{ required: true, pattern: /^[A-Za-z][A-Za-z0-9_]{0,31}$/, message: '使用字母开头的1至32位字母、数字或下划线' }]}><Input placeholder="lan" /></Form.Item></Col>
              <Col xs={24} md={8}><Form.Item name={[field.name, 'device']} label="接口名称" rules={[{ required: true, pattern: /^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/, message: '请输入有效设备名称' }]}><AutoComplete options={inventory.data?.filter(item => !item.loopback).map(item => ({ value: item.name })) ?? []} placeholder="选择或输入接口" /></Form.Item></Col>
              <Col xs={24} md={8}><Form.Item name={[field.name, 'mtu']} label="MTU" rules={[{ required: true, type: 'integer', min: 576, max: 9216 }]}><InputNumber min={576} max={9216} precision={0} /></Form.Item></Col>
            </Row>
            <Tabs items={[
              { key: 'ip', label: '静态 IP', forceRender: true, children: <Form.Item name={[field.name, 'addresses']} label="IP 地址（CIDR）" rules={[{ required: true, type: 'array', min: 1, max: 8, message: '配置1至8个IP/CIDR地址' }]}><Select mode="tags" tokenSeparators={[',', ' ', ';']} placeholder="输入IP/前缀长度后按回车" /></Form.Item> },
              { key: 'dns', label: 'DNS', forceRender: true, children: <Row gutter={16}>
                <Col xs={24} md={12}><Form.Item name={[field.name, 'dns']} label="DNS 服务器" rules={[{ type: 'array', max: 6 }]}><Select mode="tags" tokenSeparators={[',', ' ', ';']} placeholder="输入DNS服务器IP" /></Form.Item></Col>
                <Col xs={24} md={12}><Form.Item name={[field.name, 'search']} label="DNS 搜索域" rules={[{ type: 'array', max: 6 }]}><Select mode="tags" tokenSeparators={[',', ' ', ';']} placeholder="输入ASCII域名" /></Form.Item></Col>
              </Row> },
              { key: 'routes', label: '静态路由', forceRender: true, children: <Form.List name={[field.name, 'routes']}>{(routes, actions) => <>
                {routes.map(route => <Row key={route.key} gutter={12} align="top">
                  <Col xs={24} md={8}><Form.Item name={[route.name, 'destination']} label="目标网络（CIDR）" rules={[{ required: true }]}><Input placeholder="0.0.0.0/0" /></Form.Item></Col>
                  <Col xs={24} md={8}><Form.Item name={[route.name, 'gateway']} label="下一跳" rules={[{ required: true }]}><Input placeholder="网关IP" /></Form.Item></Col>
                  <Col xs={16} md={5}><Form.Item name={[route.name, 'metric']} label="Metric" rules={[{ required: true, type: 'integer', min: 0, max: 4294967295 }]}><InputNumber min={0} max={4294967295} precision={0} /></Form.Item></Col>
                  <Col xs={8} md={3}><Button aria-label={`删除路由 ${route.name + 1}`} icon={<DeleteOutlined />} onClick={() => actions.remove(route.name)} /></Col>
                </Row>)}
                <Button icon={<PlusOutlined />} disabled={busy || routes.length >= 128} onClick={() => actions.add({ destination: '', gateway: '', metric: 100 })}>添加路由</Button>
              </>}</Form.List> },
            ]} />
          </ProCard>)}
          <Form.ErrorList errors={errors} />
          <Space wrap>
            <Button icon={<PlusOutlined />} disabled={!ready || busy || fields.length >= 32} onClick={() => add({ id: `lan${fields.length + 1}`, device: '', mtu: 1500, addresses: [], dns: [], search: [], routes: [] })}>添加接口配置</Button>
            <Button type="primary" loading={busy} disabled={!ready || !state.data?.capabilities.can_preview} onClick={() => void submit('preview')}>校验并预览</Button>
            {state.data?.capabilities.can_preflight && <Button loading={busy} disabled={!ready} onClick={() => void submit('preflight')}>应用前检查</Button>}
            {state.data?.capabilities.can_validate_native && <Button loading={busy} disabled={!ready} onClick={() => void submit('native')}>原生工具校验</Button>}
            <Tooltip title={state.data?.capabilities.can_save ? '' : '需要管理员认证并启用配置存储'}><Button disabled={!ready || !state.data?.capabilities.can_save || conflict || busy} onClick={() => void submit('save')}>保存草稿</Button></Tooltip>
          </Space>
        </div>}
      </Form.List>
    </Form>}
    <Drawer closable={{ "aria-label": "关闭" }} title="持久配置来源" size="min(1040px, 100vw)" open={Boolean(persistent)} onClose={() => setPersistent(null)} destroyOnHidden>{persistent && <PersistentNetworkResult report={persistent} />}</Drawer>
    <Drawer closable={{ "aria-label": "关闭" }} title="原生工具校验" size="min(860px, 100vw)" open={Boolean(nativeValidation)} onClose={() => setNativeValidation(null)} destroyOnHidden>{nativeValidation && <NetworkNativeValidationResult report={nativeValidation} />}</Drawer>
    <Drawer closable={{ "aria-label": "关闭" }} title="应用前检查" size="min(960px, 100vw)" open={Boolean(report)} onClose={() => setReport(null)} destroyOnHidden>{report && <NetworkPreflightResult report={report} />}</Drawer>
    <Drawer closable={{ "aria-label": "关闭" }} title="原生配置预览" size="min(760px, 100vw)" open={Boolean(preview)} onClose={() => setPreview(null)} destroyOnHidden>
      {preview && <Space orientation="vertical" size="large" style={{ width: '100%' }}>
        <Alert type="info" title="校验已完成，配置尚未应用" showIcon />
        <ProDescriptions column={1} dataSource={{}} columns={[{ title: '配置摘要', render: () => <Typography.Text copyable style={{ wordBreak: 'break-all' }}>{preview.digest}</Typography.Text> }]} />
        <Tabs items={preview.artifacts.map(artifact => ({ key: artifact.name, label: artifact.name, children: <Input.TextArea className="mono" aria-label={artifact.name} readOnly rows={20} value={artifact.content} spellCheck={false} /> }))} />
      </Space>}
    </Drawer>
  </div></PageContainer>;
}
