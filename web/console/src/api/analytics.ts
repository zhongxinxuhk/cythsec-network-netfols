import { ApiError } from './client';
import type { ApiEnvelope } from './types';

export interface CaptureStatus {
  input_complete: boolean;
  analysis_complete: boolean;
  capture_loss_status: 'unknown' | 'declared_zero' | 'declared_nonzero' | 'inconsistent_counters';
  published_windows: number;
  suppressed_windows: number;
  source_counter_consistent: boolean | null;
}
export interface AggregateImport {
  id: string;
  stored_at: string;
  windows: number;
  first_window_seconds: number | null;
  last_window_seconds: number | null;
  bytes: number;
  status: CaptureStatus;
}
export interface AggregateWindow {
  window_start_seconds: number;
  window_seconds: number;
  sampling_interval: number;
  suppressed: boolean;
  statistics: {
    contributing_sampled_flows: number;
    tcp_packets: number;
    udp_packets: number;
    other_ip_packets: number;
    tls_record_candidate_packets: number | null;
    quic_long_header_candidate_packets: number | null;
    integrity: {
      records: number;
      snaplen_truncated: number;
      decode_incomplete: number;
      unparsed_fragments: number;
      fragmented_transport: number;
      capacity_rejected_packets: number;
      late_records: number;
      timestamp_regressions: number;
    };
    tcp_quality: {
      retransmission_candidates: number;
      out_of_order_candidates: number;
      forward_gap_candidates: number;
      response_delay_samples: number | null;
      response_delay_upper_bounds_ms: (number | null)[];
      response_delay_histogram: number[] | null;
    } | null;
  } | null;
}
export interface AggregatePage {
  import: AggregateImport;
  items: AggregateWindow[];
  total: number;
  offset: number;
  limit: number;
}
export interface AggregateQuery { from?: number; to?: number; offset: number; limit: number }
const BASE = (import.meta.env.VITE_TELEMETRYD_BASE as string) || '/telemetry/api/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try { res = await fetch(`${BASE}/analytics/imports${path}`, init); }
  catch (e) {
    if (e instanceof Error && e.name === 'AbortError') throw e;
    throw new ApiError('无法连接聚合存储服务');
  }
  const body = await res.json() as ApiEnvelope<T>;
  if (!res.ok || body.error) throw new ApiError(body.error || `HTTP ${res.status}`, res.status);
  return body.data;
}
export const analytics = {
  imports: (signal?: AbortSignal) => request<{ items: AggregateImport[]; total: number }>('', { signal }),
  windows: (id: string, query: AggregateQuery, signal?: AbortSignal) => {
    const params = new URLSearchParams();
    Object.entries(query).forEach(([key, value]) => { if (value !== undefined) params.set(key, String(value)); });
    return request<AggregatePage>(`/${encodeURIComponent(id)}?${params}`, { signal });
  },
  upload: async (file: File) => {
    if (file.size > 1024 * 1024) throw new ApiError('聚合文件不能超过 1 MiB');
    return request<{ import: AggregateImport; duplicate: boolean; durable: boolean }>('', {
      method: 'POST', headers: { 'Content-Type': 'application/x-ndjson' }, body: await file.text(),
    });
  },
};
