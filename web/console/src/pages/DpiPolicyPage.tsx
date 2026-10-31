import { useEffect, useMemo, useState } from 'react';
import { PageContainer, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Input, Radio, Space, Switch, Tag, Typography } from 'antd';
import { ReloadOutlined, SaveOutlined } from '@ant-design/icons';
import { dpiPolicy } from '@/api/dpi';
import type { DpiIntensity, DpiModule, DpiPolicy, DpiState } from '@/api/dpi';
import { Card } from '@/components/Card';

const intensityText: Record<DpiIntensity, string> = {
  off: '关闭：不运行任何检测器，记录写 not_inspected（不冒充 unknown）。',
  basic: '基础：只运行 TLS ClientHello、HTTP 首部、DNS，检查窗口 128 字节。',
  standard: '标准：全部已启用模块按首包判定，窗口沿用采集上限（默认 512 字节）。',
  deep: '深度：窗口至少 4096 字节；配置密钥日志后可尝试解密 TLS 1.3 应用数据。',
};
const availabilityText: Record<DpiModule['availability'], { color: string; label: string }> = {
  implemented: { color: 'green', label: '已实现' },
  context: { color: 'blue', label: '明文入口' },
  candidate: { color: 'orange', label: '结构候选' },
};
const errorText = (error: unknown) => (error instanceof Error ? error.message : 'DPI 策略请求失败');

function clone(policy: DpiPolicy): DpiPolicy {
  return JSON.parse(JSON.stringify(policy)) as DpiPolicy;
}

export function DpiPolicyPage() {
  const [modules, setModules] = useState<DpiModule[]>([]);
  const [state, setState] = useState<DpiState | null>(null);
  const [draft, setDraft] = useState<DpiPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState('');

  async function load() {
    setLoading(true); setError(null); setNotice('');
    try {
      const [catalog, current] = await Promise.all([dpiPolicy.modules(), dpiPolicy.read()]);
      setModules(catalog.modules);
      setState(current);
      setDraft(clone(current.snapshot.policy));
    } catch (cause) {
      setError(errorText(cause));
      setState(null); setDraft(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  const dirty = useMemo(
    () => Boolean(draft && state && JSON.stringify(draft) !== JSON.stringify(state.snapshot.policy)),
    [draft, state],
  );
  const canSave = Boolean(state?.capabilities.can_save);

  function update(patch: Partial<DpiPolicy>) {
    setDraft((current) => (current ? { ...current, ...patch } : current));
  }

  function updateModule(key: string, enabled: boolean) {
    setDraft((current) => (current ? { ...current, modules: { ...current.modules, [key]: enabled } } : current));
  }

  async function save() {
    if (!draft || !state || !canSave || saving) return;
    if (draft.tls_decrypt.enabled && !draft.tls_decrypt.keylog_file.trim()) {
      setError('启用 TLS 解密前必须填写运维方提供的 key log 绝对路径');
      return;
    }
    if (draft.tls_decrypt.enabled && !draft.tls_decrypt.keylog_file.startsWith('/')) {
      setError('TLS key log 必须使用绝对路径');
      return;
    }
    setSaving(true); setError(null); setNotice('');
    try {
      const snapshot = await dpiPolicy.save(draft, state.snapshot.revision);
      const next: DpiState = { ...state, snapshot };
      setState(next);
      setDraft(clone(snapshot.policy));
      setNotice(`策略已保存为版本 ${snapshot.revision}；数据面在下次启动或下次分析读取该文件时生效。`);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setSaving(false);
    }
  }

  const columns: ProColumns<DpiModule>[] = [
    {
      title: '模块', dataIndex: 'name', key: 'name', width: 220,
      render: (_, module) => <Space orientation="vertical" size={0}>
        <span>{module.name}</span>
        <Typography.Text type="secondary" className="small">{module.key} · {module.catalog_ids.join(' / ')}</Typography.Text>
      </Space>,
    },
    { title: '分组', dataIndex: 'group', key: 'group', width: 180 },
    {
      title: '类型', dataIndex: 'availability', key: 'availability', width: 110,
      render: (_, module) => <Tag color={availabilityText[module.availability].color}>{availabilityText[module.availability].label}</Tag>,
    },
    {
      title: '启用', key: 'enabled', width: 90,
      render: (_, module) => <Switch
        checked={draft?.modules[module.key] ?? module.default_enabled}
        checkedChildren="开"
        unCheckedChildren="关"
        aria-label={`${module.name} 模块开关`}
        onChange={(enabled) => updateModule(module.key, enabled)}
      />,
    },
    {
      title: '说明', key: 'note',
      render: (_, module) => module.note || '—',
    },
  ];

  const disabledModules = draft ? Object.entries(draft.modules).filter(([, enabled]) => !enabled).length : 0;

  return <PageContainer content="按协议启停 DPI 模块、调整检测强度，并配置运维方提供的 TLS 密钥日志">
    <div className="page-stack">
      <Card
        title="DPI 运行策略"
        subtitle="保存的是数据面读取的策略文件；控制面不声称已热更新正在运行的进程。"
        loading={loading}
        error={error}
      >
        {!state && !loading && <Alert type="warning" title="未能读取 DPI 策略" showIcon role="alert" />}
        {state && !state.capabilities.store_enabled && <Alert
          type="warning"
          showIcon
          title="未启用 DPI 策略存储"
          description="routerd 未配置 -dpi-policy-dir，本页只能查看默认策略，无法保存。"
        />}
        {state && state.capabilities.store_enabled && !canSave && <Alert
          type="info"
          showIcon
          title="当前身份为只读"
          description="保存策略需要管理员身份；请通过控制台连接具备 admin 角色的服务凭据。"
        />}
        {notice && <Alert type="success" title={notice} showIcon role="status" />}

        {draft && state && <>
          <Space align="center" size="large" wrap>
            <Space>
              <Typography.Text strong>深度包检测</Typography.Text>
              <Switch
                checked={draft.enabled && draft.intensity !== 'off'}
                aria-label="DPI 总开关"
                onChange={(enabled) => update({ enabled, intensity: enabled ? (draft.intensity === 'off' ? 'standard' : draft.intensity) : 'off' })}
              />
            </Space>
            <Typography.Text type="secondary">策略版本 {state.snapshot.revision} · 已关闭 {disabledModules} 个模块</Typography.Text>
          </Space>

          <div className="dpi-intensity">
            <Typography.Text strong>检测强度</Typography.Text>
            <Radio.Group
              value={draft.intensity}
              optionType="button"
              buttonStyle="solid"
              disabled={!draft.enabled}
              aria-label="DPI 检测强度"
              onChange={(event) => update({ intensity: event.target.value as DpiIntensity })}
              options={[
                { value: 'off', label: '关闭' },
                { value: 'basic', label: '基础' },
                { value: 'standard', label: '标准' },
                { value: 'deep', label: '深度' },
              ]}
            />
            <Typography.Paragraph type="secondary">{intensityText[draft.intensity]}</Typography.Paragraph>
          </div>

          <Space orientation="vertical" className="dpi-tls">
            <Space align="center">
              <Typography.Text strong>TLS 1.3 应用数据解密</Typography.Text>
              <Switch
                checked={draft.tls_decrypt.enabled}
                aria-label="TLS 解密开关"
                onChange={(enabled) => update({ tls_decrypt: { ...draft.tls_decrypt, enabled } })}
              />
              <Tag color="orange">仅 deep 生效</Tag>
            </Space>
            <Input
              value={draft.tls_decrypt.keylog_file}
              aria-label="TLS key log 路径"
              placeholder="/var/lib/cythsec/tls.keys（NSS key log，由运维方提供）"
              onChange={(event) => update({ tls_decrypt: { ...draft.tls_decrypt, keylog_file: event.target.value } })}
            />
            <Typography.Text type="secondary">
              只读取密钥日志解密已有流量，不做主动探测、不导出或猜测密钥；没有密钥时保持仅识别可见 ClientHello。
            </Typography.Text>
          </Space>

          <Space>
            <Button type="primary" icon={<SaveOutlined />} onClick={() => void save()} loading={saving} disabled={!canSave || !dirty}>
              保存策略
            </Button>
            <Button icon={<ReloadOutlined />} onClick={() => void load()} disabled={saving}>重新读取</Button>
            {dirty && <Typography.Text type="warning">有未保存的修改</Typography.Text>}
          </Space>

          <ProTable<DpiModule>
            rowKey="key"
            columns={columns}
            dataSource={modules}
            search={false}
            options={false}
            pagination={false}
            size="small"
            scroll={{ x: 960 }}
          />
        </>}
      </Card>
    </div>
  </PageContainer>;
}
