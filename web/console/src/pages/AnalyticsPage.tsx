import { useEffect, useState } from 'react';
import { analytics } from '@/api/analytics';
import type { AggregateImport, AggregatePage, AggregateQuery } from '@/api/analytics';
import { Card } from '@/components/Card';
import { fmtBytes, fmtInt } from '@/utils/format';

const lossLabels = {
  unknown: '来源丢包未知', declared_zero: '来源声明零丢包',
  declared_nonzero: '来源声明存在丢包', inconsistent_counters: '来源计数不一致',
};
const count = (value: number | null | undefined) => (value === null || value === undefined) ? '未发布' : fmtInt(value);
const message = (e: unknown) => e instanceof Error ? e.message : '请求失败';

export function AnalyticsPage() {
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

  const status = page?.import.status;
  return (
    <div className="page analytics-page">
      <Card title="聚合历史分析" subtitle="承载协议、TCP 质量与采集完整性">
        <p className="muted">按采集批次查询分钟窗口。不同批次可能重叠，不跨批次合计；未发布指标不作为零值。</p>
        <div className="analytics-toolbar">
          <label>导入聚合 JSONL
            <input type="file" accept=".jsonl,.ndjson" disabled={uploading} onChange={(e) => {
              const file = e.target.files?.[0]; e.target.value = ''; if (!file) return;
              setUploading(true); setError(null); setNotice('');
              void analytics.upload(file).then((data) => {
                if (!data.durable) throw new Error('存储未确认持久化');
                setSelected(data.import.id); setQuery({ offset: 0, limit: 100 });
                setNotice(data.duplicate ? '该批次已存在，未重复写入' : '批次已持久化');
                setRevision((v) => v + 1);
              }).catch((e: unknown) => setError(message(e))).finally(() => setUploading(false));
            }} />
          </label>
          <button className="btn" type="button" onClick={() => setRevision((v) => v + 1)}>刷新历史</button>
        </div>
        {uploading && <p role="status">正在校验并保存…</p>}
        {notice && <p role="status">{notice}</p>}
        {error && <p role="alert" className="error-text">{error}</p>}
        {(loading || listLoading) && <p role="status">正在读取历史…</p>}
        {!loading && !listLoading && !error && imports.length === 0 && <p>尚无聚合历史。请导入 cythsec-observe 输出的 JSONL 文件。</p>}
        {imports.length > 0 && <>
          <label className="analytics-batch">采集批次
            <select value={selected} onChange={(e) => { setSelected(e.target.value); setQuery({ offset: 0, limit: 100 }); setFrom(''); setTo(''); }}>
              {imports.map((item) => <option key={item.id} value={item.id}>
                {new Date(item.stored_at).toLocaleString()} · {item.windows} 窗 · {item.id.slice(0, 10)}
              </option>)}
            </select>
          </label>
          <form className="analytics-toolbar" onSubmit={(e) => {
            e.preventDefault();
            const start = from ? new Date(from).getTime() / 1000 : undefined;
            const end = to ? new Date(to).getTime() / 1000 : undefined;
            if ((start !== undefined && (!Number.isSafeInteger(start) || start < 0)) ||
                (end !== undefined && (!Number.isSafeInteger(end) || end < 0)) ||
                (start !== undefined && end !== undefined && start >= end)) { setError('请选择有效的起止时间'); return; }
            setQuery({ from: start, to: end, offset: 0, limit: 100 });
          }}>
            <label>起始时间<input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
            <label>结束时间<input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} /></label>
            <button className="btn" type="submit">查询窗口</button>
            <span className="muted small">本机时区；按窗口起点，结束时间不包含在范围内。</span>
          </form>
        </>}
      </Card>
      {page && status && <Card title="采集与存储状态" subtitle={`已持久化 ${fmtBytes(page.import.bytes)} · ${page.import.windows} 个窗口`}>
        <p className={status.input_complete && status.analysis_complete ? '' : 'error-text'}>
          文件读取：{status.input_complete ? '完成' : '不完整'} · 分析处理：{status.analysis_complete ? '完成' : '不完整'} · {lossLabels[status.capture_loss_status]}
        </p>
        <p className="muted small">持久化成功只表示数据已保存，不能证明采集无丢包；处理完成也不代表全部报文均可解码。</p>
      </Card>}
      {page && <Card title="承载与质量窗口" subtitle={`匹配 ${page.total} 窗 · 每页最多 100 窗`}>
        {page.items.length === 0 && <p>当前时间范围没有窗口。</p>}
        <div className="analytics-table">
          <table className="tbl">
            <thead><tr><th>窗口 / 采样</th><th>TCP / UDP / 其他 IP</th><th>TLS / QUIC 头候选</th><th>重传 / 乱序 / 缺口候选</th><th>完整性与时差</th></tr></thead>
            <tbody>{page.items.map((window) => {
              const s = window.statistics, q = s?.tcp_quality, i = s?.integrity;
              return <tr key={window.window_start_seconds}>
                <td>{new Date(window.window_start_seconds * 1000).toLocaleString()}<div className="muted small">{window.window_seconds}s · 1:{window.sampling_interval}</div></td>
                {window.suppressed || !s ? <td colSpan={4}>样本流数不足，统计已抑制</td> : <>
                  <td>{count(s.tcp_packets)} / {count(s.udp_packets)} / {count(s.other_ip_packets)}</td>
                  <td>{count(s.tls_record_candidate_packets)} / {count(s.quic_long_header_candidate_packets)}</td>
                  <td>{count(q?.retransmission_candidates)} / {count(q?.out_of_order_candidates)} / {count(q?.forward_gap_candidates)}</td>
                  <td>{i && <div>{i.records} 条记录 · 截断 {i.snaplen_truncated} · 容量拒绝 {i.capacity_rejected_packets} · 迟到 {i.late_records}<div className="muted small">头不全 {i.decode_incomplete} · 非首片 {i.unparsed_fragments} · 首片 {i.fragmented_transport} · 时间回退 {i.timestamp_regressions}</div></div>}
                    {q?.response_delay_histogram ? <details><summary>SYN 响应时差（{q.response_delay_samples} 样本）</summary>
                      <ol className="analytics-histogram">{q.response_delay_histogram.map((n, index) => <li key={index}>
                        <span>{index === 0 ? '0' : q.response_delay_upper_bounds_ms[index - 1]}～{q.response_delay_upper_bounds_ms[index] ?? '∞'} ms</span>
                        <meter min={0} max={Math.max(1, q.response_delay_samples || 0)} value={n} aria-label={`时差桶 ${index + 1}`} /> {n}
                      </li>)}</ol>
                    </details> : <div className="muted small">时差分布未发布</div>}
                  </td>
                </>}
              </tr>;
            })}</tbody>
          </table>
        </div>
        <div className="analytics-toolbar">
          <button className="btn" disabled={query.offset === 0 || loading} onClick={() => setQuery((old) => ({ ...old, offset: Math.max(0, old.offset - 100) }))}>上一页</button>
          <button className="btn" disabled={query.offset + page.items.length >= page.total || loading} onClick={() => setQuery((old) => ({ ...old, offset: old.offset + 100 }))}>下一页</button>
        </div>
        <p className="muted small">TLS／QUIC 为采样后的头部候选计数；序号缺口不等于网络丢包，SYN 响应时差不等于网站加载时延。</p>
      </Card>}
    </div>
  );
}
