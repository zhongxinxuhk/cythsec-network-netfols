import { Alert, Col, Row, Statistic } from 'antd';
import type { IngestStatus } from '@/api/analytics';
import { Card } from './Card';
import { fmtBytes } from '@/utils/format';

const states = { disabled: '未启用', stopped: '已停止', idle: '等待批次', writing: '正在写入历史', backoff: '退避重试中', blocked: '需要处理后重启' };
const errors: Record<string, string> = {
  queue_requires_restart: '队列状态需重启校验', storage_requires_restart: '历史存储状态需重启校验',
  queue_data_invalid: '待写批次校验失败，已保留原文件', storage_full: '历史存储容量已满，待写批次仍保留',
  storage_data_invalid: '历史数据校验失败，需检查存储', storage_io: '历史存储写入失败，将重试',
  queue_ack_failed: '历史已确认保存，但队列确认失败，重启后安全重试',
};
export function IngestPanel({ status, error }: { status: IngestStatus | null; error: string | null }) {
  return <Card title="持续写入队列" subtitle="状态每 3 秒刷新；接收确认与历史保存分别显示">
    {error ? <Alert type="error" title={`队列状态不可用：${error}；上传暂不可用，已有历史仍可查询`} showIcon role="status" /> : !status ? <p>正在读取队列状态…</p> : !status.enabled ?
      <p className="muted">未启用磁盘队列，文件仍通过同步导入保存。</p> : <>
        <p>{states[status.state]} · {status.running ? '工作进程运行中' : '工作进程未运行'}</p>
        <Row gutter={[24, 16]}>
          <Col xs={24} md={8}><Statistic title={`待写批次 / ${status.max_batches}`} value={status.pending_batches} /></Col>
          <Col xs={24} md={8}><Statistic title={`待写数据 / ${fmtBytes(status.max_bytes)}`} value={fmtBytes(status.pending_bytes)} /></Col>
          <Col xs={24} md={8}><Statistic title="本次进程已确认批次" value={status.completed_this_process} /></Col>
        </Row>
        {status.oldest_queued_at && <p>最早待写：{new Date(status.oldest_queued_at).toLocaleString()}</p>}
        {status.last_error && <p role="status" className="error-text">{errors[status.last_error] || '写入状态异常，请检查服务'}</p>}
        {status.next_retry_at && <p>下次重试：{new Date(status.next_retry_at).toLocaleString()}</p>}
        <p className="muted small">失败次数 {status.failures_this_process} · 连续失败 {status.consecutive_failures} · 去重重试 {status.duplicates_this_process}。进程计数在重启后归零，磁盘待写批次会恢复。</p>
        <p className="muted small">进入队列表示待写数据已落盘，尚不代表历史保存完成。容量满时拒绝新批次，发送端须保留输入。</p>
      </>}
  </Card>;
}
