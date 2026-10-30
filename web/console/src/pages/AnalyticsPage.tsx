import { useEffect, useRef, useState } from 'react';
import { PageContainer, ProTable, type ProColumns } from '@ant-design/pro-components';
import { Alert, Button, Collapse, DatePicker, Empty, Form, Progress, Select, Space, Typography, Upload } from 'antd';
import { ReloadOutlined, UploadOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import { serviceAccess } from '@/api/http';
import { useApi } from '@/hooks/useApi';
import { analytics } from '@/api/analytics';
import type { AggregateImport, AggregatePage, AggregateQuery, AggregateWindow } from '@/api/analytics';
import { useIngestStatus } from '@/hooks/useIngestStatus';
import { IngestPanel } from '@/components/IngestPanel';
import { Card } from '@/components/Card';
import { fmtBytes, fmtInt } from '@/utils/format';

const lossLabels = {
  unknown: '来源丢包未知', declared_zero: '来源声明零丢包',
  declared_nonzero: '来源声明存在丢包', inconsistent_counters: '来源计数不一致',
};
const count = (value: number | null | undefined) => (value === null || value === undefined) ? '未发布' : fmtInt(value);
const message = (e: unknown) => e instanceof Error ? e.message : '请求失败';

export function AnalyticsPage() {
  const access = useApi(() => serviceAccess('telemetryd'), 10000);
  const canUpload = Boolean(access.data && (!access.data.enabled || access.data.can_ingest));
  const { status: ingest, error: ingestError } = useIngestStatus();
  const pendingSelection = useRef<string | null>(null);
  const [imports, setImports] = useState<AggregateImport[]>([]);
  const [selected, setSelected] = useState('');
  const [page, setPage] = useState<AggregatePage | null>(null);
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [query, setQuery] = useState<AggregateQuery>({ offset: 0, limit: 100 });

  useEffect(() => {
    const controller = new AbortController();
    setListLoading(true); setError(null);
    analytics.imports(controller.signal).then((data) => {
      if (controller.signal.aborted) return;
      setImports(data.items);
      if (pendingSelection.current && data.items.some((item) => item.id === pendingSelection.current)) {
        setSelected(pendingSelection.current); pendingSelection.current = null;
        setNotice('历史批次已可查询');
      }
      setSelected((old) => data.items.some((item) => item.id === old) ? old : data.items[0]?.id || '');
      setListLoading(false);
    }).catch((e: unknown) => { if (!controller.signal.aborted) { setError(message(e)); setListLoading(false); } });
    return () => controller.abort();
  }, [revision]);

  useEffect(() => {
    setPage(null); setLoading(Boolean(selected));
    if (!selected) return;
    const controller = new AbortController();
    setLoading(true); setError(null);
    analytics.windows(selected, query, controller.signal).then((data) => {
      if (!controller.signal.aborted) { setPage(data); setLoading(false); }
    }).catch((e: unknown) => { if (!controller.signal.aborted) { setError(message(e)); setLoading(false); } });
    return () => controller.abort();
  }, [selected, query, revision]);

  useEffect(() => {
    if (ingest?.enabled) setRevision((value) => value + 1);
  }, [ingest?.enabled, ingest?.completed_this_process]);

  async function upload(file: File) {
    if (uploading || !ingest || !canUpload) return;
    setUploading(true); setError(null); setNotice('');
    try {
      if (ingest.enabled) {
        const data = await analytics.enqueue(file);
        if (!data.durable || data.acknowledged_stage !== 'queue') throw new Error('队列未确认持久化');
        pendingSelection.current = data.id;
        setNotice(data.duplicate ? '该批次已在待写队列，历史写入尚未确认' : '已进入持久化待写队列，历史写入尚未确认');
      } else {
        const data = await analytics.upload(file);
        if (!data.durable) throw new Error('存储未确认持久化');
        setSelected(data.import.id);
        setNotice(data.duplicate ? '该批次已存在，未重复写入' : '批次已持久化');
      }
      setQuery({ offset: 0, limit: 100 }); setFrom(''); setTo(''); setRevision((v) => v + 1);
    } catch (e) { setError(message(e)); }
    finally { setUploading(false); }
  }
  const columns: ProColumns<AggregateWindow>[] = [
    { title: '窗口 / 采样', key: 'window', width: 220, render: (_, window) => <>
      {new Date(window.window_start_seconds * 1000).toLocaleString()}<div className="muted small">{window.window_seconds}s · 1:{window.sampling_interval}</div>
    </> },
    { title: 'TCP / UDP / 其他 IP', key: 'transport', width: 200, render: (_, window) => window.suppressed || !window.statistics ? '样本流数不足，统计已抑制' : `${count(window.statistics.tcp_packets)} / ${count(window.statistics.udp_packets)} / ${count(window.statistics.other_ip_packets)}` },
    { title: 'TLS / QUIC 头候选', key: 'encrypted', width: 180, render: (_, window) => window.suppressed || !window.statistics ? '未发布' : `${count(window.statistics.tls_record_candidate_packets)} / ${count(window.statistics.quic_long_header_candidate_packets)}` },
    { title: '重传 / 乱序 / 缺口候选', key: 'quality', width: 220, render: (_, window) => window.suppressed || !window.statistics ? '未发布' : `${count(window.statistics.tcp_quality?.retransmission_candidates)} / ${count(window.statistics.tcp_quality?.out_of_order_candidates)} / ${count(window.statistics.tcp_quality?.forward_gap_candidates)}` },
    { title: '完整性与时差', key: 'integrity', width: 400, render: (_, window) => {
      const q = window.statistics?.tcp_quality, i = window.statistics?.integrity;
      if (window.suppressed || !window.statistics) return '未发布';
      return <>
        {i && <div>{i.records} 条记录 · 截断 {i.snaplen_truncated} · 容量拒绝 {i.capacity_rejected_packets} · 迟到 {i.late_records}<div className="muted small">头不全 {i.decode_incomplete} · 非首片 {i.unparsed_fragments} · 首片 {i.fragmented_transport} · 时间回退 {i.timestamp_regressions}</div></div>}
        {q?.response_delay_histogram ? <Collapse size="small" items={[{ key: 'delay', label: `SYN 响应时差（${q.response_delay_samples} 样本）`, children: q.response_delay_histogram.map((n, index) => <div key={q.response_delay_upper_bounds_ms[index] ?? "infinity"}>
          <span>{index === 0 ? '0' : q.response_delay_upper_bounds_ms[index - 1]}～{q.response_delay_upper_bounds_ms[index] ?? '∞'} ms · {n}</span>
          <Progress percent={100 * n / Math.max(1, q.response_delay_samples || 0)} showInfo={false} aria-label={`时差桶 ${index + 1}`} />
        </div>) }]} /> : <Typography.Text type="secondary">时差分布未发布</Typography.Text>}
      </>;
    } },
  ];
  const status = page?.import.status;
  return <PageContainer content="承载协议、TCP 质量与采集完整性"><div className="page-stack">
    <Card title="聚合历史分析" subtitle="按采集批次查询分钟窗口">
      <Typography.Paragraph type="secondary">不同批次可能重叠，不跨批次合计；未发布指标不作为零值。仅接收聚合 JSONL，最大 1 MiB。</Typography.Paragraph>
      <Space wrap>
        <Upload accept=".jsonl,.ndjson" showUploadList={false} disabled={uploading || !ingest || !canUpload} beforeUpload={(file) => { void upload(file); return false; }}>
          <Button icon={<UploadOutlined />} disabled={uploading || !ingest || !canUpload} loading={uploading}>导入聚合 JSONL</Button>
        </Upload>
        <Button icon={<ReloadOutlined />} onClick={() => setRevision((v) => v + 1)} loading={listLoading}>刷新历史</Button>
      </Space>
      {uploading && <p role="status">正在校验并保存…</p>}
      {notice && <Alert type="info" title={notice} showIcon role="status" />}
      {error && <Alert type="error" title={error} showIcon role="alert" />}
      {(loading || listLoading) && <p role="status">正在读取历史…</p>}
      {!loading && !listLoading && !error && imports.length === 0 && <Empty description="尚无聚合历史。请导入 cythsec-observe 输出的 JSONL 文件。" />}
      {imports.length > 0 && <Form layout="vertical" onKeyDown={(event) => {
        // DatePicker 的回车用于确认日期；查询由提交按钮触发，避免只选起点就隐式提交。
        if (event.key === 'Enter' && event.target instanceof HTMLInputElement) event.preventDefault();
      }} onFinish={() => {
        const start = from ? dayjs(from).unix() : undefined;
        const end = to ? dayjs(to).unix() : undefined;
        if ((start !== undefined && (!Number.isSafeInteger(start) || start < 0)) ||
            (end !== undefined && (!Number.isSafeInteger(end) || end < 0)) ||
            (start !== undefined && end !== undefined && start >= end)) { setError('请选择有效的起止时间'); return; }
        setError(null); setQuery({ from: start, to: end, offset: 0, limit: 100 });
      }}>
        <Form.Item label="采集批次" htmlFor="aggregate-batch">
          <Select id="aggregate-batch" className="analytics-batch" value={selected} onChange={(id) => { setSelected(id); setQuery({ offset: 0, limit: 100 }); setFrom(''); setTo(''); }} options={imports.map((item) => ({ value: item.id, label: `${new Date(item.stored_at).toLocaleString()} · ${item.windows} 窗 · ${item.id.slice(0, 10)}` }))} />
        </Form.Item>
        <Space wrap align="start">
          <Form.Item label="起始时间" htmlFor="window-from"><DatePicker id="window-from" showTime needConfirm={false} format="YYYY-MM-DD HH:mm:ss" value={from ? dayjs(from) : null} onChange={(value) => setFrom(value?.format() || '')} /></Form.Item>
          <Form.Item label="结束时间" htmlFor="window-to"><DatePicker id="window-to" showTime needConfirm={false} format="YYYY-MM-DD HH:mm:ss" value={to ? dayjs(to) : null} onChange={(value) => setTo(value?.format() || '')} /></Form.Item>
          <Form.Item label=" "><Button type="primary" htmlType="submit">查询窗口</Button></Form.Item>
        </Space>
        <Typography.Paragraph type="secondary">本机时区；按窗口起点，结束时间不包含在范围内。</Typography.Paragraph>
      </Form>}
    </Card>
    {access.error && <Alert type="warning" title={`访问权限不可用：${access.error}；上传暂不可用`} />}
    {access.data?.enabled && !access.data.can_ingest && <Alert type="info" title="当前身份只读，可查询历史，不能导入批次。" />}
    <IngestPanel status={ingest} error={ingestError} />
    {page && status && <Card title="采集与存储状态" subtitle={`已持久化 ${fmtBytes(page.import.bytes)} · ${page.import.windows} 个窗口`}>
      <Alert showIcon type={status.input_complete && status.analysis_complete && status.capture_loss_status === 'declared_zero' ? 'success' : 'warning'} title={`文件读取：${status.input_complete ? '完成' : '不完整'} · 分析处理：${status.analysis_complete ? '完成' : '不完整'} · ${lossLabels[status.capture_loss_status]}`} description="持久化成功只表示数据已保存，不能证明采集无丢包；处理完成也不代表全部报文均可解码。" />
    </Card>}
    {page && <ProTable<AggregateWindow> headerTitle={`承载与质量窗口 · 匹配 ${page.total} 窗`} rowKey="window_start_seconds" columns={columns} dataSource={page.items} loading={loading} search={false} options={{ density: false, reload: () => setRevision((v) => v + 1) }} scroll={{ x: 1220 }}
      pagination={{ current: Math.floor(query.offset / 100) + 1, total: page.total, pageSize: 100, showSizeChanger: false, showTotal: (total) => `共 ${total} 个窗口`, onChange: (current) => setQuery((old) => ({ ...old, offset: (current - 1) * 100 })) }}
      locale={{ emptyText: '当前时间范围没有窗口。' }}
      footer={() => 'TLS／QUIC 为采样后的头部候选计数；序号缺口不等于网络丢包，SYN 响应时差不等于网站加载时延。'} />}
  </div></PageContainer>;
}
export default AnalyticsPage;
